package org.gmssl.gui.engine;

import static org.gmssl.gui.engine.EngineModels.*;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.Flow;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.stereotype.Service;

@Service
public class ExecutionService {
    private final CatalogService catalog;
    private final EngineValidator validator;
    private final EngineSettings settings;
    private final Semaphore slots;
    private final Map<String,Live> active=new ConcurrentHashMap<>();
    private final Set<String> seen=ConcurrentHashMap.newKeySet();
    private final Set<String> cancelledIds=ConcurrentHashMap.newKeySet();
    private final AtomicBoolean cleanupFailure=new AtomicBoolean();
    private final java.util.concurrent.ExecutorService io=Executors.newVirtualThreadPerTaskExecutor();
    private static final class Live { volatile Process process; volatile java.util.concurrent.CompletableFuture<?> httpFuture; final AtomicBoolean cancelled=new AtomicBoolean(); }
    public ExecutionService(CatalogService catalog, EngineValidator validator, EngineSettings settings) throws IOException {
        this.catalog=catalog; this.validator=validator; this.settings=settings; slots=new Semaphore(settings.maxProcesses);
        rejectSymlinks(settings.work);
        Files.createDirectories(settings.work);
        permissions(settings.work,"rwx------");
    }
    public ExecutionResponse execute(ExecutionRequest request) {
        if(request==null||request.id()==null)throw EngineException.invalid();
        try { if(!UUID.fromString(request.id()).toString().equals(request.id()))throw EngineException.invalid(); } catch(IllegalArgumentException e) { throw EngineException.invalid(); }
        JsonNode tool=catalog.tool(request.toolId());
        if(tool.path("verification").path("status").asText().equals("unavailable"))throw new EngineException(400,"UNAVAILABLE","Tool is unavailable in this deployment");
        Map<String,List<String>> params=validator.validate(tool,request.parameters());
        int timeout=request.timeoutSeconds()==null?tool.path("defaultTimeoutSeconds").asInt(30):request.timeoutSeconds();
        if(timeout<1||timeout>Math.min(300,tool.path("maxTimeoutSeconds").asInt(300)))throw EngineException.invalid();
        if(cleanupFailure.get())throw new EngineException(503,"CLEANUP_QUARANTINE","Work storage requires administrator recovery");
        if(!slots.tryAcquire())throw new EngineException(429,"BUSY","Execution capacity reached");
        if(seen.size()>100000) {slots.release();throw new EngineException(503,"RESTART_REQUIRED","Execution identity capacity reached");}
        if(!seen.add(request.id())) {slots.release();throw new EngineException(409,"DUPLICATE_EXECUTION","Execution identity has already been used");}
        Live live=new Live(); active.put(request.id(),live);
        if(cancelledIds.contains(request.id()))live.cancelled.set(true);
        Path directory=null;
        List<byte[]> sensitive=new ArrayList<>();
        long start=System.nanoTime();
        try {
            if(live.cancelled.get())return new ExecutionResponse(request.id(),"CANCELLED",null,"","",0,false,List.of(),List.of());
            rejectSymlinks(settings.runner);
            if(!Files.isRegularFile(settings.runner,LinkOption.NOFOLLOW_LINKS)||!Files.isExecutable(settings.runner))throw new EngineException(503,"RUNNER_UNAVAILABLE","Native runner unavailable");
            rejectSymlinks(settings.work);
            directory=Files.createTempDirectory(settings.work,"job-"); permissions(directory,"rwx------");
            Path inputs=Files.createDirectory(directory.resolve("input")), outputs=Files.createDirectory(directory.resolve("output"));
            permissions(inputs,"rwx------"); permissions(outputs,"rwx------");
            Map<String,Path> inputPaths=new HashMap<>();
            int inputBytes=0;
            if(request.inputs()!=null) {
                if(request.inputs().size()>64)throw EngineException.invalid();
                for(var entry:request.inputs().entrySet()) {
                    String token=entry.getKey();
                    if(!token.matches("[A-Za-z0-9_-]{1,64}")||entry.getValue()==null)throw EngineException.invalid();
                    byte[] bytes=decode(entry.getValue().contentBase64()); sensitive.add(bytes);
                    inputBytes=Math.addExact(inputBytes,bytes.length); if(inputBytes>settings.maxBytes)throw new EngineException(413,"INPUT_LIMIT","Input limit exceeded");
                    Path path=inputs.resolve(token+".bin"); Files.write(path,bytes,StandardOpenOption.CREATE_NEW); permissions(path,"rw-------"); inputPaths.put(token,path);
                }
            }
            byte[] stdin=request.stdinBase64()==null?new byte[0]:decode(request.stdinBase64()); sensitive.add(stdin);
            if((long)inputBytes+stdin.length>settings.maxBytes)throw new EngineException(413,"INPUT_LIMIT","Input limit exceeded");
            if(stdin.length>0&&!tool.path("acceptsStdin").asBoolean())throw EngineException.invalid();
            if(tool.path("command").asText().equals("crlget")) {
                if(live.cancelled.get()) return new ExecutionResponse(request.id(),"CANCELLED",null,"","",0,false,List.of(),List.of());
                Path certFile=inputPaths.get(params.get("cert").getFirst().substring(6));
                if(certFile==null) throw EngineException.invalid();
                byte[] certBytes=readRegular(certFile,settings.maxBytes); sensitive.add(certBytes);
                String crlUri=extractCrlUri(certBytes);
                if(crlUri==null) throw new EngineException(400,"INVALID_CERTIFICATE","Certificate does not contain valid HTTP CRL distribution points");
                URI uri; try { uri=URI.create(crlUri); } catch(IllegalArgumentException e) { throw new EngineException(400,"NETWORK_POLICY","Invalid CRL distribution point URI"); }
                validator.network.validateUri(uri);
                long deadlineNanos = start + TimeUnit.SECONDS.toNanos(timeout);
                byte[] crlBytes=fetchCrl(uri,deadlineNanos,live,sensitive);
                if(live.cancelled.get()) return new ExecutionResponse(request.id(),"CANCELLED",null,"","",0,false,List.of(),List.of());
                Path crlTmp=directory.resolve("crl_verify.der");
                Files.write(crlTmp,crlBytes,StandardOpenOption.CREATE_NEW); permissions(crlTmp,"rw-------");
                validateCrlNative(crlTmp,directory,deadlineNanos,live);
                List<Artifact> artifacts=new ArrayList<>();
                if(params.containsKey("out")) {
                    String outName=params.get("out").getFirst();
                    Path outFile=outputs.resolve(outName);
                    Files.write(outFile,crlBytes,StandardOpenOption.CREATE_NEW); permissions(outFile,"rw-------");
                    artifacts.add(new Artifact(outName,"application/octet-stream",Base64.getEncoder().encodeToString(crlBytes)));
                }
                String stdoutEncoded=Base64.getEncoder().encodeToString(crlBytes);
                cleanupChecked(directory); directory=null;
                return new ExecutionResponse(request.id(),"SUCCEEDED",0,stdoutEncoded,"",Duration.ofNanos(System.nanoTime()-start).toMillis(),false,artifacts,List.of());
            }
            List<String> arguments=new ArrayList<>(); arguments.add(tool.path("command").asText());
            for(JsonNode p:tool.path("parameters")) {
                String name=p.path("name").asText();
                if(!params.containsKey(name))continue;
                for(String raw:params.get(name)) {
                    arguments.add(p.path("flag").asText());
                    if(p.path("type").asText().equals("BOOLEAN"))continue;
                    String value=raw;
                    if(p.path("type").asText().equals("INPUT_FILE")) {
                        Path file=inputPaths.get(raw.substring(6)); if(file==null)throw EngineException.invalid(); value=file.toString();
                    } else if(p.path("type").asText().equals("OUTPUT_FILE")) value=outputs.resolve(raw).toString();
                    arguments.add(value);
                }
            }
            String stateToken=null;
            if(tool.path("stateful").asBoolean()) { List<String> key=params.get("key"); if(key==null||key.size()!=1)throw EngineException.invalid(); stateToken=key.getFirst().substring(6); }
            byte[] frame=frame(arguments); sensitive.add(frame);
            ProcessBuilder builder=new ProcessBuilder(settings.runner.toString()); builder.directory(directory.toFile());
            builder.environment().clear(); builder.environment().put("LANG","C"); builder.environment().put("LC_ALL","C");
            Process process=builder.start(); live.process=process;
            if(live.cancelled.get())stop(process);
            Capture stdout=new Capture(settings.maxBytes), stderr=new Capture(Math.min(settings.maxBytes,1024*1024));
            var outFuture=io.submit(()->stdout.drain(process.getInputStream(),process));
            var errFuture=io.submit(()->stderr.drain(process.getErrorStream(),process));
            var writer=io.submit(()-> {try(var pipe=process.getOutputStream()) {pipe.write(frame);pipe.write(stdin);}catch(IOException ignored){} });
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(timeout);
            boolean finished=false, outputExceeded=false;
            while(!(finished=process.waitFor(50,TimeUnit.MILLISECONDS)) && System.nanoTime()<deadline) {
                if(live.cancelled.get()) { stop(process); break; }
                if(outputSize(outputs)>settings.maxBytes) {outputExceeded=true;stop(process);break;}
            }
            if(!finished)stop(process);
            if(live.cancelled.get())stop(process);
            process.waitFor(3,TimeUnit.SECONDS);
            writer.get(3,TimeUnit.SECONDS);outFuture.get(3,TimeUnit.SECONDS);errFuture.get(3,TimeUnit.SECONDS);
            Integer exit=process.isAlive()?null:process.exitValue();
            boolean truncated=stdout.truncated||stderr.truncated||outputExceeded;
            String status=live.cancelled.get()?"CANCELLED":!finished?"TIMED_OUT":exit!=null&&exit==0&&!truncated?"SUCCEEDED":"FAILED";
            List<Artifact> artifacts=new ArrayList<>();
            List<UpdatedInput> updated=new ArrayList<>();
            int outputBytes=stdout.size();
            if(status.equals("SUCCEEDED")) {
                try(var files=Files.list(outputs)) {
                    for(Path file:files.sorted().toList()) {
                        byte[] bytes=readRegular(file,settings.maxBytes); sensitive.add(bytes); outputBytes=Math.addExact(outputBytes,bytes.length);
                        if(outputBytes>settings.maxBytes)throw new EngineException(413,"OUTPUT_LIMIT","Output limit exceeded");
                        artifacts.add(new Artifact(file.getFileName().toString(),"application/octet-stream",Base64.getEncoder().encodeToString(bytes)));
                    }
                }
                if(stateToken!=null) {byte[] bytes=readRegular(inputPaths.get(stateToken),settings.maxBytes);sensitive.add(bytes);updated.add(new UpdatedInput(stateToken,Base64.getEncoder().encodeToString(bytes)));}
            }
            String diagnostic=sanitize(stderr.text(),directory,tool,params);
            byte[] stdoutBytes=stdout.bytes(); sensitive.add(stdoutBytes);
            String encodedStdout=status.equals("SUCCEEDED")?Base64.getEncoder().encodeToString(stdoutBytes):"";
            cleanupChecked(directory); directory=null;
            stdout.clear();stderr.clear();
            return new ExecutionResponse(request.id(),status,exit,encodedStdout,diagnostic,Duration.ofNanos(System.nanoTime()-start).toMillis(),truncated,artifacts,updated);
        } catch(EngineException e) {throw e;}
          catch(Exception e) {if(live.process!=null)stop(live.process); throw new EngineException(500,"EXECUTION_ERROR","Native execution failed");}
        finally {
            if(live.process!=null&&live.process.isAlive())stop(live.process);
            active.remove(request.id()); slots.release();
            for(byte[] bytes:sensitive)Arrays.fill(bytes,(byte)0);
            if(directory!=null) {try{cleanupChecked(directory);}catch(EngineException ignored){cleanupFailure.set(true);}}
        }
    }
    public boolean cancel(String id) {
        try{UUID.fromString(id);}catch(Exception e){throw EngineException.invalid();}
        if(cancelledIds.size()>100000)throw new EngineException(503,"CANCEL_CAPACITY","Cancellation identity capacity reached");
        cancelledIds.add(id);
        Live live=active.get(id);
        if(live==null)return true;
        live.cancelled.set(true);
        if(live.process!=null)stop(live.process);
        if(live.httpFuture!=null)live.httpFuture.cancel(true);
        return true;
    }
    static void stop(Process p) { List<ProcessHandle> children=p.descendants().toList();for(var child:children)child.destroy();p.destroy();try{p.waitFor(200,TimeUnit.MILLISECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();}for(var child:children)if(child.isAlive())child.destroyForcibly();if(p.isAlive())p.destroyForcibly(); }
    static void rejectSymlinks(Path path) throws IOException {Path current=path.toAbsolutePath().getRoot();for(Path part:path.toAbsolutePath()){current=current.resolve(part);if(Files.isSymbolicLink(current))throw new IOException("Symlink path rejected");}}
    public boolean tryAcquireSlot() { return slots.tryAcquire(); }
    public void releaseSlot() { slots.release(); }
    static void permissions(Path path,String mode)throws IOException {if(Files.getFileStore(path).supportsFileAttributeView("posix"))Files.setPosixFilePermissions(path,PosixFilePermissions.fromString(mode));}
    static byte[] readRegular(Path path,int max)throws IOException {rejectSymlinks(path);if(!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)||Files.size(path)>max)throw new IOException("Artifact rejected");try(InputStream in=Files.newInputStream(path,LinkOption.NOFOLLOW_LINKS)){byte[] b=in.readNBytes(max+1);if(b.length>max)throw new IOException("Artifact limit");return b;}}
    private byte[] decode(String data) {if(data==null||data.length()>(long)settings.maxBytes*4/3+8)throw EngineException.invalid();try{return Base64.getDecoder().decode(data);}catch(IllegalArgumentException e){throw EngineException.invalid();}}
    static byte[] frame(List<String> arguments)throws IOException {if(arguments.isEmpty()||arguments.size()>256)throw EngineException.invalid();ByteArrayOutputStream buffer=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(buffer);out.write("GMRUN001".getBytes(StandardCharsets.US_ASCII));out.writeInt(arguments.size());List<byte[]> encoded=new ArrayList<>();int total=0;for(String value:arguments){byte[] b=value.getBytes(StandardCharsets.UTF_8);if(b.length>65536||value.indexOf(0)>=0)throw EngineException.invalid();total=Math.addExact(total,b.length);encoded.add(b);}if(total>1048576)throw EngineException.invalid();out.writeInt(total);for(byte[] b:encoded){out.writeInt(b.length);out.write(b);Arrays.fill(b,(byte)0);}return buffer.toByteArray();}
    private static String sanitize(String text,Path directory,JsonNode tool,Map<String,List<String>> values) {
        for(JsonNode p:tool.path("parameters"))if(p.path("secret").asBoolean()||p.path("type").asText().equals("SECRET"))for(String value:values.getOrDefault(p.path("name").asText(),List.of()))if(!value.isEmpty())text=text.replace(value,"[redacted]");
        text=text.replace(directory.toString(),"[task]");
        if(tool.path("sensitiveOutput").asBoolean()||tool.path("category").asText().equals("protocol"))return text.isBlank()?"":"Native diagnostics suppressed for sensitive execution";
        return text.replaceAll("[\\p{Cntrl}&&[^\\n\\t]]","?");
    }
    boolean healthy() { return !cleanupFailure.get(); }
    void cleanupChecked(Path directory) {
        try { Path absolute=directory.toAbsolutePath().normalize();
            if(!absolute.startsWith(settings.work)||absolute.equals(settings.work))throw new IOException("Cleanup boundary");
            try(var files=Files.walk(absolute)){for(Path p:files.sorted(java.util.Comparator.reverseOrder()).toList()){
                if(!p.toAbsolutePath().normalize().startsWith(absolute))throw new IOException("Cleanup boundary");Files.deleteIfExists(p);}}
            if(Files.exists(absolute,LinkOption.NOFOLLOW_LINKS))throw new IOException("Cleanup incomplete");
        } catch(IOException e){cleanupFailure.set(true);throw new EngineException(503,"CLEANUP_QUARANTINE","Work storage requires administrator recovery");}
    }
    static long outputSize(Path directory)throws IOException {
        long size=0;try(var files=Files.walk(directory)){for(Path file:files.toList()){
            if(Files.isSymbolicLink(file))throw new IOException("Output symlink");
            if(Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS))size=Math.addExact(size,Files.size(file));
        }}return size;
    }
    static class DerReader {
        final byte[] data; int pos; final int end;
        DerReader(byte[] data, int pos, int end) {
            if (pos < 0 || end < pos || end > data.length) throw new IllegalArgumentException("Invalid DER reader slice");
            this.data=data; this.pos=pos; this.end=end;
        }
        boolean hasRemaining() { return pos < end; }
        int remaining() { return end - pos; }
        int peekTag() { return hasRemaining() ? (data[pos] & 0xFF) : -1; }
        int readTag() { if (!hasRemaining()) throw new IllegalArgumentException("Unexpected EOF reading tag"); return data[pos++] & 0xFF; }
        int readLength() {
            if (!hasRemaining()) throw new IllegalArgumentException("Unexpected EOF reading length");
            int b = data[pos++] & 0xFF;
            if (b == 0x80) throw new IllegalArgumentException("Indefinite length forbidden in DER");
            int len;
            if ((b & 0x80) == 0) {
                len = b;
            } else {
                int n = b & 0x7F;
                if (n < 1 || n > 4) throw new IllegalArgumentException("Length octets count out of range: " + n);
                if (remaining() < n) throw new IllegalArgumentException("Unexpected EOF reading multibyte length");
                len = 0;
                for (int i = 0; i < n; i++) {
                    len = (len << 8) | (data[pos++] & 0xFF);
                    if (len < 0) throw new IllegalArgumentException("Integer overflow in length");
                }
            }
            if (len < 0 || len > remaining()) throw new IllegalArgumentException("DER element length " + len + " exceeds remaining boundary " + remaining());
            return len;
        }
        DerReader readSequence() {
            int tag = readTag(); if (tag != 0x30) throw new IllegalArgumentException("Expected SEQUENCE 0x30, got 0x" + Integer.toHexString(tag));
            int len = readLength(); DerReader s = new DerReader(data, pos, pos + len); pos += len; return s;
        }
        DerReader readExplicitTag(int expected) {
            int tag = readTag(); if (tag != expected) throw new IllegalArgumentException("Expected tag 0x" + Integer.toHexString(expected) + ", got 0x" + Integer.toHexString(tag));
            int len = readLength(); DerReader s = new DerReader(data, pos, pos + len); pos += len; return s;
        }
        byte[] readOctetString() {
            int tag = readTag(); if (tag != 0x04) throw new IllegalArgumentException("Expected OCTET STRING 0x04");
            int len = readLength(); byte[] res = Arrays.copyOfRange(data, pos, pos + len); pos += len; return res;
        }
        byte[] readOid() {
            int tag = readTag(); if (tag != 0x06) throw new IllegalArgumentException("Expected OID 0x06");
            int len = readLength(); byte[] res = Arrays.copyOfRange(data, pos, pos + len); pos += len; return res;
        }
        void skipValue() { readTag(); int len = readLength(); pos += len; }
    }

    static String extractCrlUri(byte[] certBytes) {
        if (certBytes == null || certBytes.length == 0 || certBytes.length > 1048576) throw new EngineException(400,"INVALID_CERTIFICATE","Empty or oversized certificate");
        byte[] der = certBytes;
        String s = new String(certBytes, StandardCharsets.US_ASCII);
        if (s.contains("-----BEGIN")) {
            String b64 = s.replaceAll("-----[A-Z0-9 ]+-----", "").replaceAll("\\s+", "");
            try { der = Base64.getDecoder().decode(b64); } catch (IllegalArgumentException e) { throw new EngineException(400,"INVALID_CERTIFICATE","Invalid base64 encoding in certificate PEM"); }
        }
        try {
            DerReader certReader = new DerReader(der, 0, der.length);
            DerReader certSeq = certReader.readSequence();
            DerReader tbsSeq = certSeq.readSequence();
            DerReader extsSeq = null;
            while (tbsSeq.hasRemaining()) {
                if (tbsSeq.peekTag() == 0xA3) { // [3] EXPLICIT Extensions
                    extsSeq = tbsSeq.readExplicitTag(0xA3).readSequence();
                    break;
                } else {
                    tbsSeq.skipValue();
                }
            }
            if (extsSeq == null) return null;
            byte[] crlOid = new byte[]{0x55, 0x1d, 0x1f}; // 2.5.29.31 without 06 03 header
            byte[] crlExtBytes = null;
            while (extsSeq.hasRemaining()) {
                DerReader extSeq = extsSeq.readSequence();
                byte[] oid = extSeq.readOid();
                boolean isCrl = Arrays.equals(oid, crlOid);
                if (extSeq.peekTag() == 0x01) extSeq.skipValue(); // BOOLEAN critical
                byte[] val = extSeq.readOctetString();
                if (isCrl) { crlExtBytes = val; break; }
            }
            if (crlExtBytes == null) return null;
            DerReader crlPoints = new DerReader(crlExtBytes, 0, crlExtBytes.length).readSequence();
            while (crlPoints.hasRemaining()) {
                DerReader dp = crlPoints.readSequence();
                while (dp.hasRemaining()) {
                    if (dp.peekTag() == 0xA0) { // [0] distributionPoint
                        DerReader dpName = dp.readExplicitTag(0xA0);
                        if (dpName.peekTag() == 0xA0) { // [0] fullName (GeneralNames)
                            DerReader gNames = dpName.readExplicitTag(0xA0);
                            while (gNames.hasRemaining()) {
                                int gnTag = gNames.readTag();
                                int gnLen = gNames.readLength();
                                if (gnTag == 0x86) { // [6] uniformResourceIdentifier IA5String
                                    byte[] uriBytes = Arrays.copyOfRange(gNames.data, gNames.pos, gNames.pos + gnLen);
                                    gNames.pos += gnLen;
                                    String uri = new String(uriBytes, StandardCharsets.US_ASCII);
                                    if (uri.startsWith("http://")) return uri;
                                } else {
                                    gNames.pos += gnLen;
                                }
                            }
                        } else dpName.skipValue();
                    } else dp.skipValue();
                }
            }
        } catch (IllegalArgumentException e) {
            throw new EngineException(400,"INVALID_CERTIFICATE","Malformed ASN.1 DER structure in certificate: "+e.getMessage());
        }
        return null;
    }
    static final class BoundedCrlSubscriber implements HttpResponse.BodySubscriber<byte[]> {
        final int limit;
        final CompletableFuture<byte[]> result = new CompletableFuture<>();
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        Flow.Subscription subscription;
        BoundedCrlSubscriber(int limit) { this.limit = limit; }
        public CompletionStage<byte[]> getBody() { return result; }
        public void onSubscribe(Flow.Subscription s) { this.subscription = s; s.request(1); }
        public void onNext(List<ByteBuffer> buffers) {
            try {
                for (ByteBuffer b : buffers) {
                    if (b.remaining() > limit - out.size()) {
                        throw new EngineException(413, "INPUT_LIMIT", "Downloaded CRL exceeded limit");
                    }
                    byte[] bytes = new byte[b.remaining()];
                    b.get(bytes);
                    out.writeBytes(bytes);
                }
                subscription.request(1);
            } catch (Exception e) {
                subscription.cancel();
                result.completeExceptionally(e);
            }
        }
        public void onError(Throwable e) { result.completeExceptionally(e); }
        public void onComplete() { result.complete(out.toByteArray()); }
    }
    private byte[] fetchCrl(URI uri, long deadlineNanos, Live live, List<byte[]> sensitive) {
        long remainingNanos = deadlineNanos - System.nanoTime();
        if (remainingNanos <= 0 || live.cancelled.get()) throw new EngineException(504,"TIMED_OUT","CRL fetch timed out");
        Duration duration = Duration.ofNanos(remainingNanos);
        try {
            var client=HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(duration).build();
            var httpReq=HttpRequest.newBuilder().uri(uri).timeout(duration).GET().build();
            int limitBytes = Math.min(settings.maxBytes, 16*1024*1024);
            var future=client.sendAsync(httpReq, responseInfo -> {
                if (responseInfo.statusCode() != 200) {
                    return HttpResponse.BodySubscribers.mapping(
                        HttpResponse.BodySubscribers.ofByteArray(),
                        b -> new byte[0]
                    );
                }
                return new BoundedCrlSubscriber(limitBytes);
            });
            live.httpFuture=future;
            if(live.cancelled.get()) { future.cancel(true); throw new EngineException(400,"CANCELLED","Execution cancelled"); }
            HttpResponse<byte[]> resp;
            try {
                resp=future.get(remainingNanos,TimeUnit.NANOSECONDS);
            } catch(java.util.concurrent.TimeoutException e) {
                future.cancel(true);
                throw new EngineException(504,"TIMED_OUT","CRL fetch timed out");
            } catch(java.util.concurrent.CancellationException e) {
                throw new EngineException(400,"CANCELLED","Execution cancelled");
            } catch(java.util.concurrent.ExecutionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof EngineException ee) throw ee;
                if (cause instanceof HttpTimeoutException) throw new EngineException(504,"TIMED_OUT","CRL fetch timed out");
                throw new EngineException(502,"NETWORK_ERROR","Failed to connect to CRL distribution point: " + (cause != null ? cause.getMessage() : e.getMessage()));
            }
            if(resp.statusCode()!=200) throw new EngineException(502,"UPSTREAM_FAILURE","CRL distribution point returned HTTP "+resp.statusCode());
            byte[] body=resp.body();
            sensitive.add(body);
            return body;
        } catch(EngineException e) { throw e; }
        catch(Exception e) { throw new EngineException(502,"NETWORK_ERROR","Failed to connect to CRL distribution point: "+e.getMessage()); }
        finally { live.httpFuture=null; }
    }
    private void validateCrlNative(Path crlFile, Path directory, long deadlineNanos, Live live) throws Exception {
        long remainingNanos = deadlineNanos - System.nanoTime();
        if (remainingNanos <= 0 || live.cancelled.get()) throw new EngineException(504,"TIMED_OUT","CRL verification timed out");
        byte[] frame=frame(List.of("crlparse","-in",crlFile.toString()));
        ProcessBuilder builder=new ProcessBuilder(settings.runner.toString());
        builder.directory(directory.toFile());
        builder.environment().clear();
        builder.environment().put("LANG","C");
        builder.environment().put("LC_ALL","C");
        Process process=builder.start();
        live.process=process;
        if(live.cancelled.get()) stop(process);
        Capture stdout=new Capture(settings.maxBytes), stderr=new Capture(Math.min(settings.maxBytes,1024*1024));
        var outF=io.submit(()->stdout.drain(process.getInputStream(),process));
        var errF=io.submit(()->stderr.drain(process.getErrorStream(),process));
        try(var pipe=process.getOutputStream()) { pipe.write(frame); } catch(IOException ignored) {}
        boolean finished=process.waitFor(remainingNanos,TimeUnit.NANOSECONDS);
        if(!finished) { stop(process); throw new EngineException(504,"TIMED_OUT","CRL verification timed out"); }
        outF.get(1,TimeUnit.SECONDS); errF.get(1,TimeUnit.SECONDS);
        if(process.exitValue()!=0) throw new EngineException(400,"INVALID_CRL","Downloaded CRL failed native crlparse verification");
    }
    static final class Capture {
        final int limit;final ByteArrayOutputStream buffer=new ByteArrayOutputStream();volatile boolean truncated;
        Capture(int limit){this.limit=limit;}
        void drain(InputStream in,Process p){try(in){byte[] b=new byte[8192];int n;while((n=in.read(b))!=-1){int keep=Math.min(n,limit-buffer.size());if(keep>0)buffer.write(b,0,keep);if(keep<n){truncated=true;stop(p);}}Arrays.fill(b,(byte)0);}catch(IOException ignored){}}
        void clear(){byte[] b=buffer.toByteArray();Arrays.fill(b,(byte)0);buffer.reset();}byte[] bytes(){return buffer.toByteArray();}int size(){return buffer.size();}String text(){return buffer.toString(StandardCharsets.UTF_8);}
    }
}
