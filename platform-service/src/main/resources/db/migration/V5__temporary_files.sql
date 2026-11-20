alter table materials add column temporary boolean not null default false;
alter table materials add column bound_job_id varchar(36);
