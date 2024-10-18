//
//  AppleSignInManager.swift
//  FirebaseGoogleLogin
//
//  Created by Murtaza Mehmood on 18/10/2024.
//

import UIKit
import FirebaseAuth
import AuthenticationServices

// MARK: - AppleSignInUser
struct AppleSignInUser {
    let uid: String
    let name: String?
    let email: String?
}

// MARK: - AppleAuthProviderProtocol
protocol AppleAuthProviderProtocol {
    func signIn(completion: @escaping (Result<AppleSignInUser, Error>) -> Void)
    func signOut(completion: @escaping (Error?) -> Void)
}

// MARK: - AppleSignInError
enum AppleSignInError: Error {
    case missingRootScreen
    case authorizationFailed
    case authenticationFailed
}

// MARK: - AppleSignInManager
final class AppleSignInManager: NSObject, AppleAuthProviderProtocol {
    
    private var currentNonce: String?
    private let firebaseSignInHandler: FirebaseSignInHandlerProtocol
    
    init(firebaseSignInHandler: FirebaseSignInHandlerProtocol = FirebaseSignInHandler()) {
        self.firebaseSignInHandler = firebaseSignInHandler
    }
    
    private var completion: ((Result<AppleSignInUser, Error>) -> Void)?
    
    // MARK: - SignIn with Apple
    func signIn(completion: @escaping (Result<AppleSignInUser, Error>) -> Void) {
        guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
              let window = windowScene.windows.first,
              let rootViewController = window.rootViewController else {
            completion(.failure(AppleSignInError.missingRootScreen))
            return
        }
        
        self.completion = completion
        let request = createAppleIDRequest()
        let authorizationController = ASAuthorizationController(authorizationRequests: [request])
        authorizationController.delegate = self
        authorizationController.presentationContextProvider = self
        authorizationController.performRequests()
    }
    
    // MARK: - Create Apple ID Request
    private func createAppleIDRequest() -> ASAuthorizationAppleIDRequest {
        let appleIDProvider = ASAuthorizationAppleIDProvider()
        let request = appleIDProvider.createRequest()
        request.requestedScopes = [.fullName, .email]
        request.nonce = randomNonceString()
        currentNonce = request.nonce
        return request
    }
    
    // MARK: - Sign Out
    func signOut(completion: @escaping (Error?) -> Void) {
        do {
            try Auth.auth().signOut()
            completion(nil)
        } catch let error {
            completion(error)
        }
    }
    
    // MARK: - Handle Firebase Authentication
    private func signInToFirebase(credential: AuthCredential, completion: @escaping (Result<AppleSignInUser, Error>) -> Void) {
        firebaseSignInHandler.signInToFirebase(with: credential) { result in
            switch result {
            case .success(let user):
                let signInUser = AppleSignInUser(
                    uid: user.uid,
                    name: user.displayName,
                    email: user.email
                )
                completion(.success(signInUser))
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    // MARK: - Generate Random Nonce
    private func randomNonceString(length: Int = 32) -> String {
        let charset: Array<Character> =
        Array("0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._")
        var result = ""
        var remainingLength = length

        while remainingLength > 0 {
            let randoms: [UInt8] = (0..<16).map { _ in
                var random: UInt8 = 0
                let errorCode = SecRandomCopyBytes(kSecRandomDefault, 1, &random)
                if errorCode != errSecSuccess {
                    fatalError("Unable to generate nonce. SecRandomCopyBytes failed with OSStatus \(errorCode)")
                }
                return random
            }

            randoms.forEach { random in
                if remainingLength == 0 {
                    return
                }

                if random < charset.count {
                    result.append(charset[Int(random)])
                    remainingLength -= 1
                }
            }
        }

        return result
    }
}

// MARK: - ASAuthorizationControllerDelegate
extension AppleSignInManager: ASAuthorizationControllerDelegate {
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        guard let appleIDCredential = authorization.credential as? ASAuthorizationAppleIDCredential else {
            completion?(.failure(AppleSignInError.authorizationFailed))
            return
        }
        
        guard let nonce = currentNonce,
              let appleIDToken = appleIDCredential.identityToken,
              let idTokenString = String(data: appleIDToken, encoding: .utf8) else {
            completion?(.failure(AppleSignInError.authenticationFailed))
            return
        }
        
        let credential = OAuthProvider.credential(providerID: AuthProviderID.apple, idToken: idTokenString, rawNonce: nonce)
        signInToFirebase(credential: credential, completion: completion!)
    }
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        completion?(.failure(error))
    }
}

// MARK: - ASAuthorizationControllerPresentationContextProviding
extension AppleSignInManager: ASAuthorizationControllerPresentationContextProviding {
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        if #available(iOS 15, *) {
            let windowScene = UIApplication.shared.connectedScenes.first as! UIWindowScene
            return windowScene.windows.first!
        } else {
            return UIApplication.shared.windows.first!
        }
        
    }
}
