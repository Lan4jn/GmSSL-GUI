alter table artifacts add column stateful_private boolean not null default false;
create table stateful_promotions(source_artifact_id varchar(36) primary key, key_id varchar(36) not null, created_at varchar(40) not null);
