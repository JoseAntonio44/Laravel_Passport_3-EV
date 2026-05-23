<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function register(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'name'                  => 'required|string|max:255',
            'email'                 => 'required|email|max:255|unique:users',
            'password'              => 'required|string|min:8|confirmed',
        ]);

        $user = User::create($validated);

        $token = $user->createToken('auth_token')->accessToken;

        return response()->json([
            'access_token' => $token,
            'token_type'   => 'Bearer',
        ], 201);
    }

    public function login(Request $request): JsonResponse
    {
        $request->validate([
            'identifier' => 'required|string',
            'password'   => 'required|string',
        ]);

        $identifier = $request->input('identifier');
        $password   = $request->input('password');

        $byEmail = Auth::attempt(['email' => $identifier, 'password' => $password]);
        $byName  = !$byEmail && Auth::attempt(['name' => $identifier, 'password' => $password]);

        if (!$byEmail && !$byName) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        $token = Auth::user()->createToken('auth_token')->accessToken;

        return response()->json([
            'access_token' => $token,
            'token_type'   => 'Bearer',
        ]);
    }

    public function me(Request $request): JsonResponse
    {
        return response()->json($request->user());
    }

    public function logout(Request $request): JsonResponse
    {
        $request->user()->tokens()->delete();

        return response()->json(['message' => 'Successfully logged out']);
    }
}
