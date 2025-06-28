<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Dashboard - Hybrid Cryptosystem</title>
  @vite('resources/css/app.css')
</head>
<body class="bg-gray-900 text-gray-100 font-sans min-h-screen">

  <!-- Navbar -->
  <nav class="bg-gray-800 px-4 py-4 flex justify-between items-center">
    <div class="text-cyan-400 font-bold text-xl">Hybrid Cryptosystem</div>

    <!-- Profile Dropdown -->
    <div class="relative">
      <button onclick="toggleDropdown()" class="text-gray-300 hover:text-white focus:outline-none">
        {{ Auth::user()->name }}
        <svg class="inline-block h-4 w-4 ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      <div id="dropdownMenu" class="hidden absolute right-0 mt-2 w-40 bg-gray-700 rounded shadow-md z-50">
        <a href="{{ route('profile.edit') }}" class="block px-4 py-2 text-gray-300 hover:bg-gray-600">Profile</a>

        <!-- Logout form -->
        <form method="POST" action="{{ route('logout') }}">
          @csrf
          <button type="submit" class="w-full text-left px-4 py-2 text-gray-300 hover:bg-gray-600">
            Log Out
          </button>
        </form>
      </div>
    </div>
  </nav>

  <div class="max-w-7xl mx-auto px-4 py-10">
    <h1 class="text-4xl font-extrabold text-cyan-400 mb-8 text-center">
      Welcome, {{ Auth::user()->name }}!
    </h1>

    <!-- Top cards flex container -->
    <div class="flex flex-col md:flex-row md:justify-evenly md:space-x-0 space-y-8 md:space-y-0">

      <!-- Encrypt Card -->
      <a href="{{ route('encrypt.form') }}" class="bg-gray-800 rounded-2xl shadow-xl p-8 flex flex-col items-center hover:bg-gray-700 transition w-full max-w-xs">
        <div class="h-12 w-12 mb-4 bg-cyan-400 rounded-full flex items-center justify-center text-gray-900 text-2xl font-bold">E</div>
        <h2 class="text-xl font-bold">Encrypt</h2>
        <p class="text-gray-400 mt-2 text-center">Encrypt your files securely using AES, RSA, or Hybrid mode.</p>
      </a>

      <!-- Decrypt Card -->
      <a href="{{ route('decrypt.form') }}" class="bg-gray-800 rounded-2xl shadow-xl p-8 flex flex-col items-center hover:bg-gray-700 transition w-full max-w-xs">
        <div class="h-12 w-12 mb-4 bg-cyan-400 rounded-full flex items-center justify-center text-gray-900 text-2xl font-bold">D</div>
        <h2 class="text-xl font-bold">Decrypt</h2>
        <p class="text-gray-400 mt-2 text-center">Decrypt files using your private key and selected algorithm.</p>
      </a>

      <!-- History Card -->
      <a href="{{ route('history') }}" class="bg-gray-800 rounded-2xl shadow-xl p-8 flex flex-col items-center hover:bg-gray-700 transition w-full max-w-xs">
        <div class="h-12 w-12 mb-4 bg-cyan-400 rounded-full flex items-center justify-center text-gray-900 text-2xl font-bold">H</div>
        <h2 class="text-xl font-bold">History</h2>
        <p class="text-gray-400 mt-2 text-center">View encryption and decryption history with details.</p>
      </a>
    </div>

    <!-- Private Key Card -->
    <div class="flex justify-center mt-12">
      <div class="bg-gray-800 rounded-2xl shadow-xl p-8 flex flex-col items-center w-full max-w-xs">
        <div class="h-12 w-12 mb-4 bg-cyan-400 rounded-full flex items-center justify-center text-gray-900 text-2xl font-bold">🔑</div>
        <h2 class="text-xl font-bold">Download Private Key</h2>
        <p class="text-gray-400 mt-2 text-center">
          Each user must download their private key to decrypt files securely.
        </p>
        <a href="{{ route('download.private.key') }}"
           class="mt-4 bg-cyan-400 text-gray-900 font-bold py-2 px-4 rounded-lg hover:bg-cyan-300 transition">
          Download Key
        </a>
      </div>
    </div>
  </div>

  <!-- Vanilla JS toggle script -->
  <script>
    function toggleDropdown() {
      document.getElementById('dropdownMenu').classList.toggle('hidden');
    }
  </script>

</body>
</html>
