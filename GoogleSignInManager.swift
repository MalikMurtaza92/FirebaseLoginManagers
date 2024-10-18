//
//  GoogleSignInManager.swift
//  FirebaseGoogleLogin
//
//  Created by Murtaza Mehmood on 18/10/2024.
//

import UIKit
import FirebaseAuth
import FirebaseCore
import FirebaseAuth

class GoogleSignInUser: User {}

typealias GoogleSignInCompletion = (Result<GoogleSignInUser,Error>)->Void

protocol GoogleAuthProviderProtocol {
    func signIn(completion: @escaping GoogleSignInCompletion)
    func signOut(completion: @escaping (Error?)->Void)
}


enum GoogleSignInError: Error {
    case missingRootScreen
    case userCanceled
}


final class GoogleSignInManager: GoogleAuthProviderProtocol {
    
    private let firebaseSignInHandler: FirebaseSignInHandlerProtocol
    init(firebaseSignInHandler: FirebaseSignInHandlerProtocol) {
        self.firebaseSignInHandler = firebaseSignInHandler
    }
    
    func signIn(completion: @escaping GoogleSignInCompletion) {
        guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
              let window = windowScene.windows.first,
              let rootViewController = window.rootViewController else {
            completion(.failure(GoogleSignInError.missingRootScreen))
            return
        }
        
        guard let clientID = FirebaseApp.app()?.options.clientID else { return }
        
        let config = GIDConfiguration(clientID: clientID)
        GIDSignIn.sharedInstance.configuration = config
        
        GIDSignIn.sharedInstance.signIn(withPresenting: rootViewController) { result, error in
            guard error == nil else {
                let errorCode = (error! as NSError).code
                if errorCode == GIDSignInError.canceled.rawValue {
                    completion(.failure(GoogleSignInError.userCanceled))
                } else {
                    completion(.failure(error!))
                }
                return
            }
            
            guard let user = result?.user,
            let idToken = user.idToken?.tokenString else { return }
            
            let credential = GoogleAuthProvider.credential(withIDToken: idToken,
                                                           accessToken: user.accessToken.tokenString)
            
            firebaseSignInHandler.signInToFirebase(with: credential) { result in
                switch result {
                case .success(let model):
                    let user = model.user
                    completion(.success(user as! GoogleSignInUser))
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        }
    }
    
    func signOut(completion: @escaping (Error?) -> Void) {
        do {
            let firebaseAuth = Auth.auth()
            try firebaseAuth.signOut()
        } catch let error {
            print(error.localizedDescription)
            completion(error)
        }
    }
}
