package org.gmssl.gui.engine;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class EngineValidator {
    final NetworkPolicy network;
    EngineValidator(NetworkPolicy network) { this.network=network; }
    Map<String,List<String>> validate(JsonNode tool, Map<String,Object> supplied) {
        Map<String,Object> values = supplied == null ? Map.of() : supplied;
        boolean certificateSan = Set.of("certgen", "reqgen", "reqsign").contains(tool.path("command").asText());
        Map<String,List<String>> result = new java.util.LinkedHashMap<>();
        Set<String> known = new HashSet<>();
        for (JsonNode p : tool.path("parameters")) {
            String name=p.path("name").asText(), type=p.path("type").asText(); known.add(name);
            Object value=values.get(name);
            if (value == null) { if (p.path("required").asBoolean()) throw EngineException.invalid(); continue; }
            List<?> elements = value instanceof List<?> list ? list : List.of(value);
            int maxElements = certificateSan && (name.equals("subject_dns_name") || name.equals("subject_ip")) ? 64 : 16;
            if (elements.isEmpty() || elements.size()>maxElements || (elements.size()>1 && !p.path("repeatable").asBoolean())) throw EngineException.invalid();
            List<String> parsed=new ArrayList<>();
            for (Object element: elements) {
                if (type.equals("BOOLEAN")) { if (!(element instanceof Boolean)) throw EngineException.invalid(); if (Boolean.TRUE.equals(element)) parsed.add(""); continue; }
                if (!(element instanceof String) && !(type.equals("INTEGER") && element instanceof Number)) throw EngineException.invalid();
                String text=String.valueOf(element);
                if (text.indexOf(0)>=0 || text.getBytes(StandardCharsets.UTF_8).length>65536 || text.indexOf('\r')>=0 || text.indexOf('\n')>=0) throw EngineException.invalid();
                if (type.equals("INTEGER")) {
                    if (!text.matches("[0-9]{1,12}")) throw EngineException.invalid();
                    long n; try { n=Long.parseLong(text); } catch (NumberFormatException e) { throw EngineException.invalid(); }
                    if ((p.has("min") && n<p.get("min").asLong()) || (p.has("max") && n>p.get("max").asLong())) throw EngineException.invalid();
                }
                if (type.equals("HEX") && (!text.matches("[0-9a-fA-F]*") || text.length()%2!=0)) throw EngineException.invalid();
                if (type.equals("ENUM")) {
                    boolean found=false;
                    for (JsonNode option:p.path("options")) {
                        if (text.equals(option.asText()) || (text.equals("sm2sig_sm3") && option.asText().equals("sm2sign_sm3")) || (text.equals("sm2sign_sm3") && option.asText().equals("sm2sig_sm3"))) found=true;
                    }
                    if (!found && p.has("defaultValue") && text.equals(p.path("defaultValue").asText())) found=true;
                    if (!found) throw EngineException.invalid();
                }
                if (type.equals("INPUT_FILE") && !text.matches("input:[A-Za-z0-9_-]{1,64}")) throw EngineException.invalid();
                if (type.equals("OUTPUT_FILE") && !basename(text)) throw EngineException.invalid();
                parsed.add(text);
            }
            if (!parsed.isEmpty()) result.put(name,parsed);
        }
        if (!known.containsAll(values.keySet())) throw EngineException.invalid();
        if (certificateSan) validateSan(result);
        cross(tool.path("command").asText(),result);
        network.validate(tool.path("command").asText(),values);
        return result;
    }
    private static void validateSan(Map<String,List<String>> values) {
        List<String> dns = values.getOrDefault("subject_dns_name", List.of());
        List<String> ips = values.getOrDefault("subject_ip", List.of());
        if (dns.size() + ips.size() > 64) throw EngineException.invalid();
        int derBytes = 0;
        for (String name : dns) {
            if (!name.matches("[A-Za-z0-9.*-]{1,253}")) throw EngineException.invalid();
            derBytes += name.length() + (name.length() < 128 ? 2 : 3);
        }
        for (String ip : ips) derBytes += ipOctets(ip) + 2;
        // Match the native buffer: concatenated GeneralName TLVs, without the outer SEQUENCE.
        if (derBytes > 2048) throw EngineException.invalid();
    }
    private static void ipv4(String literal) {
        String[] octets = literal.split("\\.", -1);
        if (octets.length != 4) throw EngineException.invalid();
        for (String octet : octets) {
            if (!octet.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(octet) > 255) throw EngineException.invalid();
        }
    }
    private static int ipOctets(String literal) {
        if (!literal.contains(":")) { ipv4(literal); return 4; }
        if (literal.length() > 45 || !literal.matches("[0-9a-fA-F:.]+")) throw EngineException.invalid();
        if (literal.contains(".")) {
            int lastColon = literal.lastIndexOf(':');
            ipv4(literal.substring(lastColon + 1));
            literal = literal.substring(0, lastColon + 1) + "0:0";
        }
        String[] sides = literal.split("::", -1);
        if (sides.length > 2) throw EngineException.invalid();
        int groups = 0;
        for (String side : sides) {
            if (side.isEmpty()) continue;
            for (String group : side.split(":", -1)) {
                if (!group.matches("[0-9a-fA-F]{1,4}")) throw EngineException.invalid();
                groups++;
            }
        }
        if (sides.length == 2 ? groups >= 8 : groups != 8) throw EngineException.invalid();
        return 16;
    }
    static boolean basename(String s) { return s.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,95}") && !s.contains(".."); }
    private static void exclusive(Map<String,List<String>> v, String... keys) { int n=0; for(String k:keys) if(v.containsKey(k)) n++; if(n>1) throw EngineException.invalid(); }
    private static void required(Map<String,List<String>> v, String... keys) { for(String k:keys) if(!v.containsKey(k)) throw EngineException.invalid(); }
    private static String value(Map<String,List<String>> v,String key,String def) { return v.containsKey(key)?v.get(key).getFirst():def; }
    private static void bytes(Map<String,List<String>> v,String key,int... valid) { if(!v.containsKey(key)) return; int n=v.get(key).getFirst().length()/2; for(int length:valid) if(n==length)return; throw EngineException.invalid(); }
    private static void cross(String c, Map<String,List<String>> v) {
        for(String[] pair:List.of(new String[]{"hex","bin"},new String[]{"id","id_hex"},new String[]{"sm2_id","sm2_id_hex"},new String[]{"req_sm2_id","req_sm2_id_hex"},new String[]{"aad","aad_hex"},new String[]{"in","in_str"},new String[]{"peer_id","peer_id_hex"})) exclusive(v,pair);
        exclusive(v,"server","client","tlcp_server");
        if(c.startsWith("sm4_") && !c.equals("sm4_cbc_mac")) {
            exclusive(v,"encrypt","decrypt"); if(!v.containsKey("encrypt")&&!v.containsKey("decrypt"))throw EngineException.invalid();
            bytes(v,"key",c.equals("sm4_xts")?32:16);
            if(c.equals("sm4_gcm")) { int n=value(v,"iv","").length()/2; if(n<1||n>64)throw EngineException.invalid(); int tag=Integer.parseInt(value(v,"taglen","16")); if(tag<12||tag>16)throw EngineException.invalid(); }
            else if(c.equals("sm4_ccm")) { int n=value(v,"iv","").length()/2; int tag=Integer.parseInt(value(v,"taglen","16")); if(n<7||n>13||tag<4||tag>16||tag%2!=0)throw EngineException.invalid(); }
            else if(!c.equals("sm4_ff1"))bytes(v,"iv",16);
            if(c.equals("sm4_xts") && Integer.parseInt(value(v,"data_unit_size","512"))%16!=0)throw EngineException.invalid();
            if(c.equals("sm4_ff1")) { required(v,"digits"); if(!value(v,"digits","").matches("[0-9]{6,128}"))throw EngineException.invalid(); exclusive(v,"idcard","bankcard"); }
        }
        if(c.startsWith("zuc")) { bytes(v,"key",c.equals("zuc256")?32:16); if(c.equals("zuc"))bytes(v,"iv",16); if(c.equals("zuc256"))bytes(v,"iv",23); if(c.startsWith("zuc_128_")) {required(v,"count","bearer","direction"); bytes(v,"count",4);} }
        if(c.equals("ghash"))bytes(v,"h",16);
        if(c.equals("sm4_cbc_mac"))bytes(v,"key",16);
        if(c.equals("sm2verify")||c.equals("sm2encrypt")) { exclusive(v,"pubkey","cert"); if(!v.containsKey("pubkey")&&!v.containsKey("cert"))throw EngineException.invalid(); }
        if(c.endsWith("_client") || c.endsWith("_server")) {
            if(v.containsKey("key"))required(v,"pass");
            if(v.containsKey("psk_key")) { bytes(v,"psk_key",32,48); required(v,"psk_identity"); }
            bytes(v,"ticket_key",32);
            // Upstream verbose TLS can print session keys. Do not permit it over the service.
            if(v.containsKey("verbose"))throw new EngineException(400,"SECRET_DIAGNOSTICS","Protocol key diagnostics are disabled");
        }
        if(c.equals("sm2exch")||c.equals("sm9exch")) {
            String stage=value(v,"stage","");
            if(!Set.of("init","respond","confirm","finish").contains(stage))throw EngineException.invalid();
            if(v.containsKey("key"))required(v,"pass");
            if(c.equals("sm2exch")&&(v.containsKey("exch_key")||v.containsKey("exch_keyout")))required(v,"exch_pass");
        }
        for(String name:List.of("id","sm2_id","peer_id")) if(value(v,name,"").getBytes(StandardCharsets.UTF_8).length>8191)throw EngineException.invalid();
        if(c.startsWith("api_")) {
            if(c.equals("api_digest")) {
                String alg=value(v,"alg","");
                if(alg.startsWith("SHAKE")) { required(v,"outlen"); }
                else if(v.containsKey("outlen")) throw EngineException.invalid();
            }
            if(c.equals("api_aes")) {
                String mode=value(v,"mode","");
                bytes(v,"key",16,24,32);
                if(mode.equalsIgnoreCase("ECB") && v.containsKey("iv")) throw EngineException.invalid();
                if((mode.equalsIgnoreCase("CBC")||mode.equalsIgnoreCase("CTR"))) bytes(v,"iv",16);
                if(mode.equalsIgnoreCase("GCM")) {
                    int ivLen=value(v,"iv","").length()/2;
                    if(ivLen<1||ivLen>32) throw EngineException.invalid();
                    int tag=Integer.parseInt(value(v,"taglen","16"));
                    if(tag!=4&&tag!=8&&tag<12||tag>16) throw EngineException.invalid();
                }
                if(mode.equalsIgnoreCase("CCM")) {
                    int ivLen=value(v,"iv","").length()/2;
                    if(ivLen<7||ivLen>13) throw EngineException.invalid();
                    int tag=Integer.parseInt(value(v,"taglen","16"));
                    if(tag<4||tag>16||tag%2!=0) throw EngineException.invalid();
                }
                if(!mode.equalsIgnoreCase("GCM")&&!mode.equalsIgnoreCase("CCM")) {
                    if(v.containsKey("aad")||v.containsKey("taglen")) throw EngineException.invalid();
                }
            }
            if(c.equals("api_zuc_mac")||c.equals("api_zuc256_mac")) {
                bytes(v,"key",c.equals("api_zuc256_mac")?32:16);
                bytes(v,"iv",c.equals("api_zuc256_mac")?23:16);
            }
            if(c.equals("api_sm9_kem")) {
                String op=value(v,"op","");
                if(!Set.of("encrypt","decrypt").contains(op)) throw EngineException.invalid();
                if(op.equals("encrypt")) required(v,"pubmaster","cipherout");
                if(op.equals("decrypt")) required(v,"key","pass");
            }
        }
        Set<String> outputNames=new HashSet<>();
        for(String k:List.of("out","pubout","outkey","keyout","exch_keyout","secret_state_out","certout","sess_out","export"))
            if(v.containsKey(k))for(String n:v.get(k))if(!outputNames.add(n))throw EngineException.invalid();
    }
}
