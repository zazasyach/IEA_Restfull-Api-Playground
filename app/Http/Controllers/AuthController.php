<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    // Register method
    public function register(Request $request)
    {
        // Validasi input
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:6|confirmed', // Password confirmation
        ]);

        // Jika validasi gagal, kembalikan error
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 400);
        }

        // Buat pengguna baru
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password), // Enkripsi password
        ]);

        // Kembalikan respons sukses
        return response()->json(['message' => 'User registered successfully']);
    }

    // Login method
    public function login(Request $request)
    {
        // Ambil kredensial (email dan password) dari request
        $credentials = $request->only('email', 'password');

        // Cek apakah token bisa dibuat dengan kredensial yang diberikan
        if (!$token = JWTAuth::attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);  // Jika login gagal
        }

        // Jika berhasil, kembalikan token
        return $this->respondWithToken($token);
    }

    // Mengembalikan token JWT
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,               // Token JWT
            'token_type'   => 'bearer',              // Tipe token
            'expires_in'   => JWTAuth::factory()->getTTL() * 60 // Waktu kadaluarsa token dalam detik
        ]);
    }
}
