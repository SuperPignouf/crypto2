/* This script creates the tables for the DB used in
INFO-F-405 - Computer Security - Projet 2013-2014
Debruyn Anthony - Plisnier Aurélien - Delhaisse Brian - Lefebvre Alexis
--------------------------------------------------------- */

DROP TABLE IF EXISTS Keychain;	

CREATE TABLE Keychain (
  ID int(8) NOT NULL PRIMARY KEY AUTO_INCREMENT COMMENT 'The internal key in the database',
  ClientID int(8) COMMENT 'The external ID of the client',
  Login varchar(50) COMMENT 'The login',
  Password varchar(50) COMMENT 'The associated password'
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8;