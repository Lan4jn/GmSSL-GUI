import java.sql.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
public class DmBaselineProbe {
 static String stage="guard";
 static void out(String s){System.out.println("DMB " + s);}
 static String e(String k){return Objects.requireNonNull(System.getenv(k));}
 static List<String> tables=List.of("APP_USERS","SESSIONS","PROJECTS","MEMBERSHIPS","MATERIALS","JOBS","ARTIFACTS","AUDIT_EVENTS","STATEFUL_MATERIAL_HISTORY","STATEFUL_PROMOTIONS","KEY_CREDENTIALS");
 static long count(Connection c,String sql)throws SQLException{try(var s=c.createStatement();var r=s.executeQuery(sql)){r.next();return r.getLong(1);}}
 static void snapshot(Connection c)throws Exception{
  var md=c.getMetaData();int n=0;
  try(var r=md.getTables(null,"GMSSL_TEST","%",new String[]{"TABLE"})){while(r.next()){String t=r.getString("TABLE_NAME");if(tables.contains(t.toUpperCase(Locale.ROOT))||t.equalsIgnoreCase("SCHEMA_VERSION")){out("TABLE "+t);n++;}}}
  out("RECOGNIZED_TABLE_COUNT "+n);
  out("ORIGINAL_SCRIPT_UPPERCASE_TABLE_MATCHES "+count(c,"select count(*) from user_tables where table_name in ('APP_USERS','SESSIONS','PROJECTS','MEMBERSHIPS','MATERIALS','JOBS','ARTIFACTS','AUDIT_EVENTS','STATEFUL_MATERIAL_HISTORY','STATEFUL_PROMOTIONS','KEY_CREDENTIALS')"));
  for(String t:tables){out("ROWS "+t+" "+count(c,"select count(*) from "+t));try(var r=md.getIndexInfo(null,"GMSSL_TEST",t,false,false)){while(r.next()){String name=r.getString("INDEX_NAME"),col=r.getString("COLUMN_NAME");if(name!=null)out("INDEX "+t+" "+name+" "+col+" unique="+!r.getBoolean("NON_UNIQUE"));}}}
  for(String t:List.of("MATERIALS","KEY_CREDENTIALS"))try(var r=md.getColumns(null,"GMSSL_TEST",t.toLowerCase(Locale.ROOT),"%")){while(r.next()){String col=r.getString("COLUMN_NAME").toUpperCase(Locale.ROOT);if(List.of("TEMPORARY","ENCRYPTED_PASSPHRASE","PENDING","VERIFIED").contains(col))out("COLUMN "+t+"."+col+" "+r.getString("TYPE_NAME")+" size="+r.getInt("COLUMN_SIZE"));}}
  long version=count(c,"select count(*) from user_tables where upper(table_name)='SCHEMA_VERSION'");out("SCHEMA_VERSION_EXISTS "+version);
  if(version>0)try(var s=c.createStatement();var r=s.executeQuery("select version,checksum,success from schema_version order by version")){while(r.next())out("VERSION "+r.getString(1)+" checksum="+r.getString(2)+" success="+r.getString(3));}
 }
 static Map<String,Long> counts(Connection c)throws SQLException{Map<String,Long> m=new TreeMap<>();for(String t:tables)m.put(t,count(c,"select count(*) from "+t));return m;}
 static String versions(Connection c)throws SQLException{StringBuilder b=new StringBuilder();try(var st=c.createStatement();var r=st.executeQuery("select version,description,installed_on,checksum,success from schema_version order by version")){while(r.next())for(int i=1;i<=5;i++)b.append(r.getString(i)).append('|');}return b.toString();}
 static void negative(Connection c,String block,String label,int expected)throws SQLException{
  if(block.toUpperCase(Locale.ROOT).matches("(?s).*\\b(?:INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\\b.*"))throw new IllegalStateException("negative-not-readonly");
  try(var st=c.createStatement()){st.execute(block);throw new IllegalStateException("negative-did-not-fail");}catch(SQLException x){out("NEGATIVE "+label+" sqlcode="+x.getErrorCode());if(x.getErrorCode()!=expected)throw x;}
 }
 static void executeBaseline(Connection c,String path)throws Exception{
  byte[] bytes=Files.readAllBytes(Path.of(path));String text=new String(bytes,java.nio.charset.StandardCharsets.UTF_8);
  if(bytes.length!=4964)throw new IllegalStateException("identity-size");out("SQL_IDENTITY bytes=4964 structure-first-nohash");
  String clean=text.replaceAll("(?m)^\\s*--.*$", "").strip();int start=clean.indexOf("DECLARE");
  if(start<0||!clean.endsWith("/"))throw new IllegalStateException("block-parser");
  String ddl=clean.substring(0,start).strip(),block=clean.substring(start,clean.length()-1).strip();
  if(!ddl.startsWith("CREATE TABLE IF NOT EXISTS schema_version")||!ddl.endsWith(";"))throw new IllegalStateException("ddl-boundary");
  if(block.indexOf("RETURN;")<block.indexOf("IF v_cred_bin_type = 0")||block.contains("v_existing_checksum")||block.contains("v_expected_checksum"))throw new IllegalStateException("ordering-or-checksum-gate");
  ddl=ddl.substring(0,ddl.length()-1);out("PARSED_BLOCKS 2 CREATE_TABLE_AND_INTACT_PLSQL");
  String before=versions(c);if(before.isEmpty())throw new IllegalStateException("existing-metadata-required");
  stage="nohash-reentry";try(var st=c.createStatement()){st.execute(ddl);st.execute(block);}if(!before.equals(versions(c)))throw new IllegalStateException("existing-metadata-modified");out("ORIGINAL_TWO_BLOCKS_REENTRY_OLD_METADATA_UNCHANGED PASS");
  String readonly=block.replaceAll("(?s)INSERT INTO schema_version.*?;", "NULL;");stage="negative-readonly";
  negative(c,readonly.replace("SELECT success INTO v_existing_success", "SELECT 0 INTO v_existing_success"),"EXISTING_FAILED_SUCCESS",-20010);
  negative(c,readonly.replace("IF v_table_count < 11", "IF v_table_count < 12"),"MISSING_TABLE_WITH_EXISTING_SUCCESS",-20001);
  negative(c,readonly.replace("data_type = 'BIT'", "data_type = 'INVALID_TEST_TYPE'"),"WRONG_BIT_WITH_EXISTING_SUCCESS",-20002);
  negative(c,readonly.replace("data_length >= 4096", "data_length >= 999999"),"SHORT_VARBINARY_WITH_EXISTING_SUCCESS",-20003);
  if(!before.equals(versions(c)))throw new IllegalStateException("negative-metadata-modified");out("FINAL_OLD_METADATA_ALL_FIELDS_UNCHANGED PASS");
 }
 public static void main(String[] args){try{
  if(!e("DM_TEST_SCHEMA").equals("GMSSL_TEST")||!e("DM_TEST_USERNAME").equalsIgnoreCase("GMSSL_TEST"))throw new IllegalStateException("guard");
  Class.forName("dm.jdbc.driver.DmDriver");DriverManager.setLoginTimeout(10);
  try(var c=DriverManager.getConnection(e("DM_TEST_JDBC_URL"),e("DM_TEST_USERNAME"),e("DM_TEST_PASSWORD"))){
   if(!"GMSSL_TEST".equals(c.getSchema())||!"GMSSL_TEST".equalsIgnoreCase(c.getMetaData().getUserName()))throw new IllegalStateException("guard");
   out("GUARD CURRENT_SCHEMA_GMSSL_TEST_MATCH");stage="metadata";snapshot(c);if(args.length>0)executeBaseline(c,args[0]);
  }out(args.length>0?"RESULT PASS NOHASH_REENTRY_AND_FOUR_READONLY_NEGATIVES":"RESULT PASS READ_ONLY_METADATA");
 }catch(Throwable x){String code=x instanceof SQLException?" sqlcode="+((SQLException)x).getErrorCode():"";out("FAIL stage="+stage+" type="+x.getClass().getSimpleName()+code);System.exit(1);}}
}
