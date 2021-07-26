<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthController extends Controller
{
    //
    protected $registerAndLogin = true;

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|min:2|max:15',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|min:2|max:15|confirmed',
        ]);

        if($validator->fails()){
            return response()->json(['errors' => $validator->errors()], 401);
        }
        
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        if($this->registerAndLogin){
            return $this->login($request);
        }

        return response()->json($user, 201);
    } 

    public function login(Request $request)
    {
        if(!$this->registerAndLogin){
        	$validator = Validator::make($request->all(), [
            	'email' => 'required|string|email',
            	'password' => 'required|string|min:2|max:15',
        	]);

      		if($validator->fails()){
            	return response()->json(['errors' => $validator->errors()], 401);
        	}
        }

        $credentials = $request->only('email', 'password');

		//if(!$token = JWTAuth::attempt($credentials)){
		if(!$token = auth('api')->attempt($credentials)){
            return response()->json(['message' => 'Invalid Email or Password'], 401);
        }

        return response()->json(['token' => $token], 200);
    }

    public function me(Request $request)
    {
        //$user = JWTAuth::authenticate($request->token); 
        $user = auth('api')->user();
        return response()->json($user, 200);
    }

    public function logout(Request $request)
    {
		try{
            auth('api')->logout();
			//JWTAuth::invalidate($request->token);
			return response()->json(['message' => 'User logged out successfully']);
		}catch(JWTException $e){
			return response()->json(['message' => 'Sorry, the user cannot be logged out'], 500);
		}
    }

    public function refresh(Request $request)
    {
        //$refresh_token = JWTAuth::refresh($request->token);
        $refresh_token = auth('api')->refresh($request->token);
        return response()->json(['refresh_token' => $refresh_token]);
    }
}
