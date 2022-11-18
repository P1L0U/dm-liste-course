<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class UserController extends Controller
{
    public function inscription(Request $request)
    {
        $utilisateurDonnee = $request->validate([
            "nom" => ["required", "string", "max:60"],
            "prenom" => ["required", "string", "max:60"],
            "email" => ["required", "string", "email", "unique:users,email"],
            "password" => ["required", "string", "min:8", "max:50", "regex:/[A-Z]/", "regex:/[0-9]/", "regex:/[@$!%#?&]/", "confirmed"]
        ]);
        $utilisateurs = User::create([
            "nom" => $utilisateurDonnee["nom"],
            "email" => $utilisateurDonnee["email"],
            "prenom" => $utilisateurDonnee["prenom"],
            "password" => bcrypt($utilisateurDonnee["password"]),
        ]);

        return response($utilisateurs, 201);
    }

    public function connexion(Request $request)
    {
        $utilisateurDonnee = $request->validate([
            "email" => ["required", "string", "email"],
            "password" => ["required", "string", "min:8", "max:50", "regex:/[A-Z]/", "regex:/[0-9]/", "regex:/[@$!%#?&]/"]
        ]);
        $utilisateur = User::where("email", $utilisateurDonnee["email"])->first();
        if (!$utilisateur)
            return response(["message" => "Utilisateur incorrect merci de réessayer"], 401);
        if (!Hash::check($utilisateurDonnee["password"], $utilisateur->password))
            return response(["message" => "Mot de passe incorrect merci de réessayer"], 401);
        $token = $utilisateur->createToken("CLE_SECRETE")->plaintexttoken;
        return response(["utilisateur" => $utilisateur, "token" => $token], 200);
    }
}