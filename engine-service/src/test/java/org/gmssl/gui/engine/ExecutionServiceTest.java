package org.gmssl.gui.engine;

import static org.gmssl.gui.engine.EngineModels.*;
import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.env.MockEnvironment;

class ExecutionServiceTest {
    @TempDir Path temp;
    ExecutionService service;
    EngineSettings settings;
    CatalogService catalog;
    @BeforeEach void init() throws Exception {
        Path runner=Path.of("../native/.build/bin/gmssl-runner").toRealPath();
        settings=new EngineSettings(new MockEnvironment().withProperty("GMSSL_ENGINE_TOKEN","test-token-32-characters-minimum-123456")
            .withProperty("GMSSL_RUNNER_PATH",runner.toString()).withProperty("GMSSL_ENGINE_WORK_DIR",temp.toRealPath().resolve("work").toString()));
        catalog=new CatalogService(new ObjectMapper());
        service=new ExecutionService(catalog,new EngineValidator(new NetworkPolicy(settings)),settings);
    }
    static ExecutionRequest req(String tool,Map<String,Object> p,byte[] stdin) {
        return new ExecutionRequest(UUID.randomUUID().toString(),tool,p,Map.of(),stdin==null?null:Base64.getEncoder().encodeToString(stdin),5);
    }
    @Test void sm3KnownAnswerAndDirectoryCleanup() throws Exception {
        var result=service.execute(req("sm3",Map.of("bin",true),"abc".getBytes()));
        assertEquals("SUCCEEDED",result.status());
        assertEquals("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",java.util.HexFormat.of().formatHex(Base64.getDecoder().decode(result.stdoutBase64())));
        try(var files=Files.list(settings.work)){assertEquals(0,files.count());}
    }
    @Test void binaryGcmRoundTripAndAuthenticationFailure() {
        byte[] payload={0,1,2,-1,0,9,10,0,7};
        var common=Map.<String,Object>of("key","00112233445566778899aabbccddeeff","iv","00112233445566778899aabb","aad","context","taglen",16);
        var encrypt=new java.util.HashMap<>(common);encrypt.put("encrypt",true);
        var encrypted=service.execute(req("sm4_gcm",encrypt,payload));assertEquals("SUCCEEDED",encrypted.status());
        byte[] ciphertext=Base64.getDecoder().decode(encrypted.stdoutBase64());
        var decrypt=new java.util.HashMap<>(common);decrypt.put("decrypt",true);
        var decrypted=service.execute(req("sm4_gcm",decrypt,ciphertext));assertEquals("SUCCEEDED",decrypted.status());assertArrayEquals(payload,Base64.getDecoder().decode(decrypted.stdoutBase64()));
        ciphertext[ciphertext.length-1]^=1;
        var failed=service.execute(req("sm4_gcm",decrypt,ciphertext));assertEquals("FAILED",failed.status());assertEquals("",failed.stdoutBase64());assertTrue(failed.artifacts().isEmpty());
    }
    @Test void unknownFlagsAndPathTraversalRejected() {
        assertThrows(EngineException.class,()->service.execute(req("sm3",Map.of("arbitrary","-help"),null)));
        assertThrows(EngineException.class,()->service.execute(req("sm3",Map.of("out","../secret"),null)));
        assertThrows(EngineException.class,()->service.execute(req("sm3",Map.of("in","/etc/passwd"),null)));
        assertThrows(EngineException.class,()->service.execute(req("sm3",Map.of("in","input:absent"),null)));
    }
    @Test void cancellationArrivingBeforeExecutionPreventsStart() {
        var request=req("sm3",Map.of("bin",true),"abc".getBytes());
        assertTrue(service.cancel(request.id()));
        assertEquals("CANCELLED",service.execute(request).status());
        assertThrows(EngineException.class,()->service.execute(request));
    }
    @Test void duplicateExecutionRejected() {
        var request=req("sm3",Map.of("bin",true),null);service.execute(request);
        assertEquals(409,assertThrows(EngineException.class,()->service.execute(request)).status);
    }
    @Test void networkTargetPolicyRejectsMetadataDnsAndPrivilegedPort() {
        assertThrows(EngineException.class,()->service.execute(req("quic_client",Map.of("host","169.254.169.254","port",14433),null)));
        assertThrows(EngineException.class,()->service.execute(req("quic_client",Map.of("host","localhost","port",14433),null)));
        assertThrows(EngineException.class,()->service.execute(req("quic_client",Map.of("host","127.0.0.1","port",443),null)));
    }
    @Test void symlinkRejectedWithoutFollowingIt() throws Exception {
        Path target=Files.writeString(temp.resolve("secret"),"fixture");
        Path link=temp.resolve("link");Files.createSymbolicLink(link,target);
        assertThrows(java.io.IOException.class,()->ExecutionService.readRegular(link,1024));
        assertEquals("fixture",Files.readString(target));
    }
    @Test void frameBoundsAndNulRejected() throws Exception {
        assertThrows(EngineException.class,()->ExecutionService.frame(List.of("sm3\0bad")));
        assertThrows(EngineException.class,()->ExecutionService.frame(java.util.Collections.nCopies(257,"x")));
        assertTrue(ExecutionService.frame(List.of("sm3","-bin")).length>16);
    }
    @Test void outputLimitStopsAndCleansTask() throws Exception {
        var tinySettings=new EngineSettings(new MockEnvironment().withProperty("GMSSL_ENGINE_TOKEN",settings.token).withProperty("GMSSL_RUNNER_PATH",settings.runner.toString()).withProperty("GMSSL_ENGINE_WORK_DIR",temp.toRealPath().resolve("tiny").toString()).withProperty("GMSSL_ENGINE_MAX_BYTES","1024"));
        var tiny=new ExecutionService(catalog,new EngineValidator(new NetworkPolicy(tinySettings)),tinySettings);
        try {var result=tiny.execute(req("rand",Map.of("outlen",1048576,"out","random.bin"),null));assertNotEquals("SUCCEEDED",result.status());}
        catch(EngineException e){assertTrue(e.status==413||e.status==500);}
        try(var files=Files.list(tinySettings.work)){assertEquals(0,files.count());}
    }
    @Test void actualProtocolListenerTimesOutAndIsCleaned() throws Exception {
        var generated=service.execute(req("sm2keygen",Map.of("pass","fixture-pass-123","out","private.pem","pubout","public.pem"),null));
        assertEquals("SUCCEEDED",generated.status());
        String key=generated.artifacts().stream().filter(a->a.name().equals("private.pem")).findFirst().orElseThrow().contentBase64();
        Map<String,Input> inputs=Map.of("key",new Input("private.pem",key));
        var certReq=new ExecutionRequest(UUID.randomUUID().toString(),"certgen",Map.of("C","CN","CN","localhost","days",1,"key","input:key","pass","fixture-pass-123","out","cert.pem"),inputs,null,5);
        var cert=service.execute(certReq);assertEquals("SUCCEEDED",cert.status(),cert.stderr());
        String certificate=cert.artifacts().getFirst().contentBase64();
        var server=new ExecutionRequest(UUID.randomUUID().toString(),"tls13_server",Map.of("key","input:key","cert","input:cert","pass","fixture-pass-123","port",14437,"www",true,"cipher_suite","TLS_SM4_GCM_SM3","supported_group","sm2p256v1","sig_alg","sm2sig_sm3"),Map.of("key",new Input("key.pem",key),"cert",new Input("cert.pem",certificate)),null,1);
        var result=service.execute(server);assertEquals("TIMED_OUT",result.status(),result.stderr());
        try(var files=Files.list(settings.work)){assertEquals(0,files.count());}
    }
    @Test void crlFetchWorkflowAndSecurityRejections() throws Exception {
        var caKeyReq=req("sm2keygen",Map.of("pass","ca-pass-1234","out","cakey.pem","pubout","capub.pem"),null);
        var caKeyRes=service.execute(caKeyReq);assertEquals("SUCCEEDED",caKeyRes.status());
        String caKey=caKeyRes.artifacts().stream().filter(a->a.name().equals("cakey.pem")).findFirst().orElseThrow().contentBase64();

        var caCertReq=new ExecutionRequest(UUID.randomUUID().toString(),"certgen",
            Map.of("C","CN","CN","RootCA","days",30,"key","input:cakey","pass","ca-pass-1234","ca",true,"key_usage",List.of("keyCertSign","cRLSign"),"out","cacert.pem"),
            Map.of("cakey",new Input("cakey.pem",caKey)),null,5);
        var caCertRes=service.execute(caCertReq);assertEquals("SUCCEEDED",caCertRes.status());
        String caCert=caCertRes.artifacts().stream().filter(a->a.name().equals("cacert.pem")).findFirst().orElseThrow().contentBase64();

        var uKeyRes=service.execute(req("sm2keygen",Map.of("pass","user-pass","out","ukey.pem","pubout","upub.pem"),null));
        String uKey=uKeyRes.artifacts().stream().filter(a->a.name().equals("ukey.pem")).findFirst().orElseThrow().contentBase64();

        var uCertReq=new ExecutionRequest(UUID.randomUUID().toString(),"certgen",
            Map.of("C","CN","CN","user","days",5,"key","input:ukey","pass","user-pass","crl_http_uri","http://127.0.0.1:14438/valid.crl","out","usercert.pem"),
            Map.of("ukey",new Input("ukey.pem",uKey)),null,5);
        var uCertRes=service.execute(uCertReq);assertEquals("SUCCEEDED",uCertRes.status());
        String uCert=uCertRes.artifacts().getFirst().contentBase64();

        var revReq=new ExecutionRequest(UUID.randomUUID().toString(),"certrevoke",
            Map.of("in","input:ucert","reason","keyCompromise","out","revoked.der"),
            Map.of("ucert",new Input("usercert.pem",uCert)),null,5);
        var revRes=service.execute(revReq);assertEquals("SUCCEEDED",revRes.status());
        String revokedDer=revRes.artifacts().getFirst().contentBase64();

        var crlReq=new ExecutionRequest(UUID.randomUUID().toString(),"crlgen",
            Map.of("in","input:rev","cacert","input:cacert","key","input:cakey","pass","ca-pass-1234","out","crl.der"),
            Map.of("rev",new Input("revoked.der",revokedDer),"cacert",new Input("cacert.pem",caCert),"cakey",new Input("cakey.pem",caKey)),null,5);
        var crlRes=service.execute(crlReq);assertEquals("SUCCEEDED",crlRes.status());
        byte[] expectedCrlBytes=Base64.getDecoder().decode(crlRes.artifacts().getFirst().contentBase64());

        var server=com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1",14438),0);
        server.createContext("/valid.crl",ex->{
            ex.getResponseHeaders().set("Content-Type","application/pkix-crl");
            ex.sendResponseHeaders(200,expectedCrlBytes.length);
            try(var os=ex.getResponseBody()){os.write(expectedCrlBytes);}
        });
        server.createContext("/bad.crl",ex->{
            byte[] bad="NOT_A_VALID_DER_CRL".getBytes();
            ex.sendResponseHeaders(200,bad.length);
            try(var os=ex.getResponseBody()){os.write(bad);}
        });
        server.createContext("/redirect.crl",ex->{
            ex.getResponseHeaders().set("Location","http://127.0.0.1:14438/valid.crl");
            ex.sendResponseHeaders(302,-1);
            ex.close();
        });
        server.createContext("/oversized.crl",ex->{
            byte[] chunk=new byte[1024*1024];
            ex.sendResponseHeaders(200,0);
            try(var os=ex.getResponseBody()){
                for(int i=0;i<20;i++){
                    os.write(chunk);
                    os.flush();
                }
            } catch(IOException ignored){}
        });
        server.createContext("/slow.crl",ex->{
            try{Thread.sleep(3000);}catch(InterruptedException ignored){}
            ex.sendResponseHeaders(200,expectedCrlBytes.length);
            try(var os=ex.getResponseBody()){os.write(expectedCrlBytes);}
        });
        server.start();

        try {
            var getReq=new ExecutionRequest(UUID.randomUUID().toString(),"crlget",
                Map.of("cert","input:cert","out","downloaded.crl"),
                Map.of("cert",new Input("cert.pem",uCert)),null,5);
            var getRes=service.execute(getReq);
            assertEquals("SUCCEEDED",getRes.status());
            assertEquals(Base64.getEncoder().encodeToString(expectedCrlBytes),getRes.stdoutBase64());
            var artifact=getRes.artifacts().stream().filter(a->a.name().equals("downloaded.crl")).findFirst().orElseThrow();
            assertArrayEquals(expectedCrlBytes,Base64.getDecoder().decode(artifact.contentBase64()));
            try(var files=Files.list(settings.work)){assertEquals(0,files.count());}

            var badCertReq=new ExecutionRequest(UUID.randomUUID().toString(),"certgen",
                Map.of("C","CN","CN","user","days",1,"key","input:ukey","pass","user-pass","crl_http_uri","http://127.0.0.1:14438/bad.crl","out","bad.pem"),
                Map.of("ukey",new Input("ukey.pem",uKey)),null,5);
            String badCert=service.execute(badCertReq).artifacts().getFirst().contentBase64();
            var badGet=new ExecutionRequest(UUID.randomUUID().toString(),"crlget",
                Map.of("cert","input:cert"),Map.of("cert",new Input("cert.pem",badCert)),null,5);
            EngineException exB=assertThrows(EngineException.class,()->service.execute(badGet));
            assertEquals(400,exB.status);assertEquals("INVALID_CRL",exB.code);
            try(var files=Files.list(settings.work)){assertEquals(0,files.count());}

            var redCertReq=new ExecutionRequest(UUID.randomUUID().toString(),"certgen",
                Map.of("C","CN","CN","user","days",1,"key","input:ukey","pass","user-pass","crl_http_uri","http://127.0.0.1:14438/redirect.crl","out","red.pem"),
                Map.of("ukey",new Input("ukey.pem",uKey)),null,5);
            String redCert=service.execute(redCertReq).artifacts().getFirst().contentBase64();
            var redGet=new ExecutionRequest(UUID.randomUUID().toString(),"crlget",
                Map.of("cert","input:cert"),Map.of("cert",new Input("cert.pem",redCert)),null,5);
            EngineException exC=assertThrows(EngineException.class,()->service.execute(redGet));
            assertEquals(502,exC.status);assertEquals("UPSTREAM_FAILURE",exC.code);
            try(var files=Files.list(settings.work)){assertEquals(0,files.count());}

            var metaCertReq=new ExecutionRequest(UUID.randomUUID().toString(),"certgen",
                Map.of("C","CN","CN","user","days",1,"key","input:ukey","pass","user-pass","crl_http_uri","http://169.254.169.254:14438/crl","out","meta.pem"),
                Map.of("ukey",new Input("ukey.pem",uKey)),null,5);
            String metaCert=service.execute(metaCertReq).artifacts().getFirst().contentBase64();
            var metaGet=new ExecutionRequest(UUID.randomUUID().toString(),"crlget",
                Map.of("cert","input:cert"),Map.of("cert",new Input("cert.pem",metaCert)),null,5);
            EngineException exD=assertThrows(EngineException.class,()->service.execute(metaGet));
            assertEquals(400,exD.status);assertEquals("NETWORK_POLICY",exD.code);
            try(var files=Files.list(settings.work)){assertEquals(0,files.count());}

            var overCertReq=new ExecutionRequest(UUID.randomUUID().toString(),"certgen",
                Map.of("C","CN","CN","user","days",1,"key","input:ukey","pass","user-pass","crl_http_uri","http://127.0.0.1:14438/oversized.crl","out","over.pem"),
                Map.of("ukey",new Input("ukey.pem",uKey)),null,5);
            String overCert=service.execute(overCertReq).artifacts().getFirst().contentBase64();
            var overGet=new ExecutionRequest(UUID.randomUUID().toString(),"crlget",
                Map.of("cert","input:cert"),Map.of("cert",new Input("cert.pem",overCert)),null,5);
            EngineException exE=assertThrows(EngineException.class,()->service.execute(overGet));
            assertEquals(413,exE.status);assertEquals("INPUT_LIMIT",exE.code);
            try(var files=Files.list(settings.work)){assertEquals(0,files.count());}

            var slowCertReq=new ExecutionRequest(UUID.randomUUID().toString(),"certgen",
                Map.of("C","CN","CN","user","days",1,"key","input:ukey","pass","user-pass","crl_http_uri","http://127.0.0.1:14438/slow.crl","out","slow.pem"),
                Map.of("ukey",new Input("ukey.pem",uKey)),null,5);
            String slowCert=service.execute(slowCertReq).artifacts().getFirst().contentBase64();
            var slowGet=new ExecutionRequest(UUID.randomUUID().toString(),"crlget",
                Map.of("cert","input:cert"),Map.of("cert",new Input("cert.pem",slowCert)),null,1);
            EngineException exF=assertThrows(EngineException.class,()->service.execute(slowGet));
            assertEquals(504,exF.status);assertEquals("TIMED_OUT",exF.code);
            try(var files=Files.list(settings.work)){assertEquals(0,files.count());}

            var noCrlReq=new ExecutionRequest(UUID.randomUUID().toString(),"crlget",
                Map.of("cert","input:cert"),Map.of("cert",new Input("cert.pem",caCert)),null,5);
            EngineException exG=assertThrows(EngineException.class,()->service.execute(noCrlReq));
            assertEquals(400,exG.status);assertEquals("INVALID_CERTIFICATE",exG.code);
            try(var files=Files.list(settings.work)){assertEquals(0,files.count());}

            String malformedDerCert=Base64.getEncoder().encodeToString(new byte[]{0x30, 0x05, 0x02, 0x01, 0x01, 0x00});
            var malformedReq=new ExecutionRequest(UUID.randomUUID().toString(),"crlget",
                Map.of("cert","input:cert"),Map.of("cert",new Input("cert.der",malformedDerCert)),null,5);
            EngineException exH=assertThrows(EngineException.class,()->service.execute(malformedReq));
            assertEquals(400,exH.status);assertEquals("INVALID_CERTIFICATE",exH.code);
            try(var files=Files.list(settings.work)){assertEquals(0,files.count());}

            // Negative ASN.1 test 1: short length exceeds parent bounds
            String shortOverflowCert=Base64.getEncoder().encodeToString(new byte[]{0x30, 0x04, 0x30, 0x0A, 0x00, 0x00});
            var shortOverflowReq=new ExecutionRequest(UUID.randomUUID().toString(),"crlget",
                Map.of("cert","input:cert"),Map.of("cert",new Input("cert.der",shortOverflowCert)),null,5);
            EngineException exI=assertThrows(EngineException.class,()->service.execute(shortOverflowReq));
            assertEquals(400,exI.status);assertEquals("INVALID_CERTIFICATE",exI.code);
            try(var files=Files.list(settings.work)){assertEquals(0,files.count());}

            // Negative ASN.1 test 2: truncated extension sequence (extensions tag declared length exceeds TBS remaining)
            String truncExtCert=Base64.getEncoder().encodeToString(new byte[]{0x30, 0x06, 0x30, 0x04, (byte)0xA3, 0x10, 0x30, 0x02});
            var truncExtReq=new ExecutionRequest(UUID.randomUUID().toString(),"crlget",
                Map.of("cert","input:cert"),Map.of("cert",new Input("cert.der",truncExtCert)),null,5);
            EngineException exJ=assertThrows(EngineException.class,()->service.execute(truncExtReq));
            assertEquals(400,exJ.status);assertEquals("INVALID_CERTIFICATE",exJ.code);
            try(var files=Files.list(settings.work)){assertEquals(0,files.count());}
        } finally {
            server.stop(0);
        }
    }
}
