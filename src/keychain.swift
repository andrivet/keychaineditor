import Security
import Foundation

func dumpKeychainItems(secClasses: [NSString]) -> [Dictionary<String, String>] {
    var returnedItemsInGenericArray: AnyObject? = nil
    var finalArrayOfKeychainItems = [Dictionary<String, String>]()
    var status: OSStatus = -1

    let accessiblityConstants: [NSString] = [kSecAttrAccessibleAfterFirstUnlock,
                                             kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                             kSecAttrAccessibleAlways,
                                             kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                             kSecAttrAccessibleAlwaysThisDeviceOnly,
                                             kSecAttrAccessibleWhenUnlocked,
                                             kSecAttrAccessibleWhenUnlockedThisDeviceOnly]

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
                account: String,
                service: String,
                data: String,
                agroup: String? = nil) -> OSStatus {

    guard let updatedData = data.data(using: String.Encoding.utf8) else {
        NSLog("UpdateKeychainItem() -> Error while unwrapping user-supplied data.")
        exit(EXIT_FAILURE)
    }

    var query = [
        kSecClass as String         :   secClass as String,
        kSecAttrAccount as String   :   account,
        kSecAttrService as String   :   service
    ]
    if let unwrappedAGroup = agroup {
        query[kSecAttrAccessGroup as String] = unwrappedAGroup
    }

    let dataToUpdate = [kSecValueData as String : updatedData]
    let status: OSStatus = SecItemUpdate(query as CFDictionary, dataToUpdate as CFDictionary)
    return status
}

func deleteKeychainItem(secClass: CFString = kSecClassGenericPassword,
                account: String,
                service: String,
                agroup: String? = nil) -> OSStatus {

    var query = [
        kSecClass as String         :   secClass as String,
        kSecAttrAccount as String   :   account,
        kSecAttrService as String   :   service
    ]
    if let unwrappedAGroup = agroup {
        query[kSecAttrAccessGroup as String] = unwrappedAGroup
    }

    let status: OSStatus = SecItemDelete(query as CFDictionary)
    return status
}
