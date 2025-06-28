<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Login - Hybrid Cryptosystem</title>
  @vite('resources/css/app.css')
</head>
<body class="bg-gray-900 text-gray-100 font-sans flex items-center justify-center min-h-screen">

  <div class="w-full max-w-md bg-gray-800 rounded-2xl shadow-2xl p-10">
    <div class="flex flex-col items-center mb-6">
      <img src="{{ asset('images/user-icon.png') }}" alt="User Icon" class="w-20 h-20 mb-4">
      <h2 class="text-4xl font-extrabold text-cyan-400">Login</h2>
    </div>

    <form method="POST" action="{{ route('login') }}" class="space-y-6">
      @csrf

      <div>
        <label for="email" class="block mb-2 text-gray-300">Email</label>
        <input type="email" id="email" name="email" required
          class="w-full px-4 py-3 rounded-lg bg-gray-700 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-cyan-400 focus:border-cyan-400 transition" />
      </div>

      <div>
        <label for="password" class="block mb-2 text-gray-300">Password</label>
        <input type="password" id="password" name="password" required
          class="w-full px-4 py-3 rounded-lg bg-gray-700 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-cyan-400 focus:border-cyan-400 transition" />
      </div>

      <button type="submit"
        class="w-full bg-cyan-400 text-gray-900 font-bold py-3 rounded-lg hover:bg-cyan-300 hover:scale-105 transition transform duration-200 ease-out">
        Login
      </button>
    </form>

    <div class="mt-6 text-center text-sm text-gray-400 space-y-2">
      <a href="{{ route('password.request') }}" class="hover:text-cyan-400 transition">Forgot your password?</a>
      <div>
        Don't have an account?
        <a href="{{ route('register') }}" class="hover:text-cyan-400 transition">Register</a>
      </div>
    </div>
  </div>

</body>
</html>
