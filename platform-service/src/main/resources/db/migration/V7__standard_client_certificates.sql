create table standard_client_certs (
  id varchar(36) primary key,
  project_id varchar(36) not null references projects(id),
  request_id varchar(100) not null,
  csr_digest varchar(64) not null,
  device_label varchar(200) not null,
  fingerprint varchar(64) not null unique,
  serial_hex varchar(40) not null unique,
  expires_at bigint not null,
  certificate_pem text not null,
  chain_pem text not null,
  issued_at bigint not null,
  revoked_at bigint,
  unique(project_id,request_id)
);
create index std_cert_page on standard_client_certs(project_id,issued_at,id);
