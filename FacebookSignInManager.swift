//
//  FacebookSignInManager.swift
//  FirebaseGoogleLogin
//
//  Created by Murtaza Mehmood on 18/10/2024.
//

import Foundation
import FacebookCore
import FacebookLogin
import FirebaseAuth

// MARK: - FacebookSignInUser
struct FacebookSignInUser {
    let uid: String
    let name: String?
    let email: String?
    let profileImageURL: URL?
}

// MARK: - FacebookAuthProviderProtocol
protocol FacebookAuthProviderProtocol {
    func signIn(completion: @escaping (Result<FacebookSignInUser, Error>) -> Void)
    func signOut(completion: @escaping (Error?) -> Void)
}

// MARK: - FacebookSignInError
enum FacebookSignInError: Error {
    case missingRootScreen
    case userCanceled
    case authenticationFailed
}

// MARK: - FacebookSignInManager
final class FacebookSignInManager: FacebookAuthProviderProtocol {
    
    private let loginManager: LoginManager
    private let firebaseSignInHandler: FirebaseSignInHandlerProtocol
    
    init(loginManager: LoginManager = LoginManager(), firebaseSignInHandler: FirebaseSignInHandlerProtocol = FirebaseSignInHandler()) {
        self.loginManager = loginManager
        self.firebaseSignInHandler = firebaseSignInHandler
    }
    
    func signIn(completion: @escaping (Result<FacebookSignInUser, Error>) -> Void) {
        guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
              let window = windowScene.windows.first,
              let rootViewController = window.rootViewController else {
            completion(.failure(FacebookSignInError.missingRootScreen))
            return
        }
        loginManager.logIn(permissions: ["public_profile", "email"], from: rootViewController) { loginResult, error in
            if let error = error {
                completion(.failure(error))
            }
            
            if loginResult?.isCancelled ?? false {
                completion(.failure(FacebookSignInError.userCanceled))
            }
            
            guard let accessToken = loginResult?.token else { return }
            self.signInToFirebase(accessToken: accessToken.tokenString, completion: completion)
        }
    }
    
    private func signInToFirebase(accessToken: String, completion: @escaping (Result<FacebookSignInUser, Error>) -> Void) {
        let credential = FacebookAuthProvider.credential(withAccessToken: accessToken)
        firebaseSignInHandler.signInToFirebase(with: credential) { result in
            switch result {
            case .success(let user):
                let signInUser = FacebookSignInUser(uid: user.uid, name: user.displayName, email: user.email, profileImageURL: user.photoURL)
                completion(.success(signInUser))
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    func signOut(completion: @escaping (Error?) -> Void) {
        let firebaseAuth = Auth.auth()
        do {
            try firebaseAuth.signOut()
            loginManager.logOut()
            completion(nil)
        } catch let error {
            completion(error)
        }
    }
}
