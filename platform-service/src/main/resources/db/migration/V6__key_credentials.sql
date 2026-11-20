create table key_credentials(
  material_id varchar(36) primary key references materials(id) on delete cascade,
  encrypted_passphrase bytea not null,
  created_at varchar(40) not null,
  updated_at varchar(40) not null
);

alter table materials add column generation_provider varchar(20);
