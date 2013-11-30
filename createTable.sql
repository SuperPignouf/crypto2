/* This script creates the tables for the DB used in
INFO-F-405 - Computer Security - Projet 2013-2014
Debruyn Anthony - Plisnier Aurélien - Delhaisse Brian - Lefebvre Alexis
--------------------------------------------------------- */

DROP TABLE IF EXISTS Certificates;	

CREATE TABLE Publication (
  ID int(8) NOT NULL PRIMARY KEY AUTO_INCREMENT COMMENT 'The internal key in the database',
  Certificate varbinary(max), COMMENT 'The certificate'
  Time_stp timestamp default current_timestamp COMMENT 'Field used to keep mdate the date of last modification of the record'
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8;