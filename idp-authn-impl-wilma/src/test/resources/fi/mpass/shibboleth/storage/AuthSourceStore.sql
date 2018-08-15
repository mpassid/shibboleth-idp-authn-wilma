CREATE TABLE mpass_authsources_wilma (
    techId VARCHAR(200) NOT NULL PRIMARY KEY,
    description VARCHAR(200) NOT NULL,
    discoName VARCHAR(25) NOT NULL,
    discoLogoUrl VARCHAR(200) NOT NULL,
    discoStyle VARCHAR(200) NOT NULL,
    mpassUrl VARCHAR(200) NOT NULL,
    samlContextClassRef VARCHAR(200) NOT NULL,
    startTime TIMESTAMP NOT NULL,
    endTime TIMESTAMP
    );