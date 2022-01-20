<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    private $response = [
        'message' => null,
        'data' => null,
    ];

    public function register(Request $req)
    {
        $req->validate([
            'name' => 'required',
            'email' => 'required',
            'no_hp' => 'required',
            'password' => 'required',
        ]);

        $data = User::create([
            'name' => $req->name,
            'email' => $req->email,
            'no_hp' => $req->no_hp,
            'password' => Hash::make($req->password),
        ]);

        $this->response['message'] = 'Register Success';
        return response()->json($this->response, 200);
    }

    public function login(Request $req)
    {
        $req->validate([
            'email' => 'required',
            'password' => 'required',
        ]);

        $user = User::where('email', $req->email)->first();

        if (!$user || ! Hash::check($req->password, $user->password)) {
            return response()->json([
                'message' => 'Login Failed'
            ]);
        }

        $token = $user->createToken($req->device_name)->plainTextToken;
        $this->response['message'] = 'Login Success';
        $this->response['data'] = [
            'token' => $token,
        ];

        return response()->json($this->response, 200);
    }

    public function me()
    {
        $user = Auth::user();

        $this->response['message'] = 'Get User Success';
        $this->response['data'] = $user;
        
        return response()->json($this->response, 200);
    }

    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();
        $this->response['message'] = 'Logout Success';

        return response()->json($this->response, 200);
    }
}
