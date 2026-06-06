function generatePwdHash(site, password) {
  var domain = (new SPH_DomainExtractor()).extractDomain(site);
  var size = SPH_kPasswordPrefix.length;
  var data = password;

  if (data.substring(0, size) == SPH_kPasswordPrefix) {
    data = data.substring(size);
  }

  return new String(new SPH_HashedPassword(data, domain));
}