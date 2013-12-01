/* This script creates the tables for the DB used in
INFO-F-405 - Computer Security - Projet 2013-2014
Debruyn Anthony - Plisnier Aurélien - Delhaisse Brian - Lefebvre Alexis
--------------------------------------------------------- */

DROP TABLE IF EXISTS Certificates;	

CREATE TABLE Certificates (
  ID int(8) NOT NULL PRIMARY KEY AUTO_INCREMENT COMMENT 'The internal key in the database',
  Certificate varchar(1100), COMMENT 'The certificate'
  Time_stp timestamp default current_timestamp COMMENT 'Field used to keep mdate the date of last modification of the record'
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8;