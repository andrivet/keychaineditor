import Security
import Foundation

let accessiblityConstants: [NSString] = [kSecAttrAccessibleAfterFirstUnlock,
                                         kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                         kSecAttrAccessibleAlways,
                                         kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                         kSecAttrAccessibleAlwaysThisDeviceOnly,
                                         kSecAttrAccessibleWhenUnlocked,
                                         kSecAttrAccessibleWhenUnlockedThisDeviceOnly]


func dumpKeychainItems(secClasses: [NSString]) -> [Dictionary<String, String>] {
    var returnedItemsInGenericArray: AnyObject? = nil
    var finalArrayOfKeychainItems = [Dictionary<String, String>]()
    var status: OSStatus = -1

    for eachKSecClass in secClasses {
        for eachConstant in accessiblityConstants {
            let query = [
                kSecClass as String             :   eachKSecClass,
                kSecAttrAccessible as String    :   eachConstant,
                kSecMatchLimit as String        :   kSecMatchLimitAll as String,
                kSecReturnAttributes as String  :   kCFBooleanTrue as Bool,
                kSecReturnData as String        :   kCFBooleanTrue as Bool
                ] as [String : Any]

            status = SecItemCopyMatching(query as CFDictionary, &returnedItemsInGenericArray)

            if status == errSecSuccess {
              finalArrayOfKeychainItems =  finalArrayOfKeychainItems + canonicalizeTypesInReturnedDicts(secClass: eachKSecClass, items: returnedItemsInGenericArray as! Array)
            }
        }
    }

    return finalArrayOfKeychainItems
}


func updateKeychainItem(secClass: CFString = kSecClassGenericPassword,
                account: String?,
                service: String?,
                agroup: String?,
                tag: String?,
                data: String) -> OSStatus {

    guard let updatedData = data.data(using: String.Encoding.utf8) else {
        NSLog("UpdateKeychainItem() -> Error while unwrapping user-supplied data.")
        exit(EXIT_FAILURE)
    }

    var query = [ kSecClass as String : secClass as String]
    if let account = account { query[kSecAttrAccount as String] = account }
    if let service = service { query[kSecAttrService as String] = service }
    if let agroup = agroup { query[kSecAttrAccessGroup as String] = agroup }
    if let tag = tag { query[kSecAttrApplicationTag as String] = tag }

    let dataToUpdate = [kSecValueData as String : updatedData]
    let status: OSStatus = SecItemUpdate(query as CFDictionary, dataToUpdate as CFDictionary)
    return status
}


func deleteKeychainItem(secClass: CFString = kSecClassGenericPassword,
                account: String?,
                service: String?,
                agroup: String?,
                tag: String?) -> OSStatus {
  
  var status: OSStatus = errSecSuccess
  
  for eachConstant in accessiblityConstants {
    var query = [ kSecClass as String : secClass as String, kSecAttrAccessible as String : eachConstant ] as [String : Any]
    if let account = account { query[kSecAttrAccount as String] = account }
    if let service = service { query[kSecAttrService as String] = service }
    if let agroup = agroup { query[kSecAttrAccessGroup as String] = agroup }
    if let tag = tag { query[kSecAttrApplicationTag as String] = tag }

    status = SecItemDelete(query as CFDictionary)
    if status == errSecSuccess {
      return errSecSuccess
    }
  }
  return status
}
