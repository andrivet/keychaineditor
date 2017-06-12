import Foundation

let cli = CommandLine()

func handleSearch(secClasses: [NSString], query: String?) {
  guard let query = query else { cli.printError("Missing query"); cli.printUsage(); return }
  
  let items = search(for: query, in: dumpKeychainItems(secClasses: secClasses))
  print(convertToJSON(for: items))
}

func handleEdit(secClass: CFString, account: String?, service: String?, agroup: String?, tag: String?, data: String?) {
  guard let data = data else { cli.printError("Missing data"); cli.printUsage(); return }
  let status = updateKeychainItem(secClass: secClass, account: account, service: service, agroup: agroup, tag: tag, data: decodeIfBase64(for: data))
  print(errorMessage(for: status))
}

func handleDelete(secClass: CFString, account: String?, service: String?, agroup: String?, tag: String?) {
  let status = deleteKeychainItem(secClass: secClass, account: account, service: service, agroup: agroup, tag: tag)
  print(errorMessage(for: status))
}

func handleDump(secClasses: [NSString]) {
 
  let items = dumpKeychainItems(secClasses: secClasses);
  print(convertToJSON(for: items))
}

func checkOnlyOneClass(_ secClasses: [NSString]) {
  
  if secClasses.count > 1
  {
    cli.printError("Please specify only one class (-g, -n, -i, -c, or -k)")
    exit(EX_USAGE)
  }
}

/*
  Start of Program.
*/

let genericPasswords = BoolOption(shortFlag: "g", longFlag: "generic", helpMessage:"Dump Generic passwords")
let internetPasswords = BoolOption(shortFlag: "n", longFlag: "internet", helpMessage:"Dump Internet passwords")
let identities = BoolOption(shortFlag: "i", longFlag: "identities", helpMessage:"Dump Identities")
let certificates = BoolOption(shortFlag: "c", longFlag: "certificates", helpMessage:"Dump certificates")
let keys = BoolOption(shortFlag: "k", longFlag: "keys", helpMessage:"Dump Keys")
let all = BoolOption(shortFlag: "A", longFlag: "all", helpMessage:"Dump all items")

let find = StringOption(shortFlag: "f", longFlag: "find", helpMessage:"Search items")
let edit = BoolOption(shortFlag: "e", longFlag: "edit", helpMessage:"Edit items")
let delete = BoolOption(shortFlag: "d", longFlag: "delete", helpMessage:"Delete items")

let account = StringOption(shortFlag: "a", longFlag:"account", helpMessage: "Account name")
let service = StringOption(shortFlag: "s", longFlag:"service", helpMessage: "Service name")
let agroup = StringOption(shortFlag: "r", longFlag:"agroup", helpMessage: "Application Group name")
let tag = StringOption(shortFlag: "t", longFlag:"tag", helpMessage: "Application tag")

let data = StringOption(shortFlag: "v", longFlag:"data", helpMessage: "Data")

let help = BoolOption(shortFlag: "h", longFlag: "help", helpMessage:"Display command line options")

cli.addOptions(genericPasswords, internetPasswords, identities, certificates, keys, all)
cli.addOptions(find, edit, delete)
cli.addOptions(account, service, agroup, tag)
cli.addOptions(data)
cli.addOptions(help)

do
{
  try cli.parse()
}
catch
{
  cli.printUsage(error)
  exit(EX_USAGE)
}

if help.wasSet
{
  cli.printUsage()
  exit(EX_USAGE)
}

var secClasses: [NSString] = []
let secAllClasses: [NSString] = [kSecClassGenericPassword, kSecClassInternetPassword, kSecClassIdentity, kSecClassCertificate, kSecClassKey]

if genericPasswords.wasSet { secClasses.append(kSecClassGenericPassword) }
if internetPasswords.wasSet { secClasses.append(kSecClassInternetPassword) }
if identities.wasSet { secClasses.append(kSecClassIdentity) }
if certificates.wasSet { secClasses.append(kSecClassCertificate) }
if keys.wasSet { secClasses.append(kSecClassKey) }
if all.wasSet { secClasses = secAllClasses }

if secClasses.count <= 0 { secClasses = secAllClasses }

if find.wasSet
{
  handleSearch(secClasses: secClasses, query: find.value)
}
else if edit.wasSet
{
  checkOnlyOneClass(secClasses)
  handleEdit(secClass: secClasses[0], account: account.value, service: service.value, agroup: agroup.value, tag: tag.value, data: data.value)
}
else if delete.wasSet
{
  checkOnlyOneClass(secClasses)
  handleDelete(secClass: secClasses[0], account: account.value, service: service.value, agroup: agroup.value, tag: tag.value)
}
else
{
  handleDump(secClasses: secClasses)
}
