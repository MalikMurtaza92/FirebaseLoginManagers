//
//  FirebaseAuthManager.swift
//  FirebaseGoogleLogin
//
//  Created by Murtaza Mehmood on 18/10/2024.
//

import Foundation
import FirebaseAuth

// MARK: - FirebaseSignInHandlerProtocol
protocol FirebaseSignInHandlerProtocol {
    func signInToFirebase(with credential: AuthCredential, completion: @escaping (Result<User, Error>) -> Void)
}

// MARK: - FirebaseSignInHandler
final class FirebaseSignInHandler: FirebaseSignInHandlerProtocol {
    
    func signInToFirebase(with credential: AuthCredential, completion: @escaping (Result<User, Error>) -> Void) {
        Auth.auth().signIn(with: credential) { authResult, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let user = authResult?.user else {
                completion(.failure(NSError(domain: "FirebaseAuth", code: -1, userInfo: [NSLocalizedDescriptionKey: "Authentication failed."])))
                return
            }
            
            completion(.success(user))
        }
    }
}
