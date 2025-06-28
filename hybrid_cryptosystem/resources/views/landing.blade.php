<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hybrid Cryptosystem</title>
    @vite('resources/css/app.css')
</head>
<body class="bg-gray-900 text-gray-100 font-sans">

    <!-- Hero Section -->
    <section class="min-h-screen flex flex-col justify-center items-center text-center px-4">
        <h1 class="text-4xl md:text-6xl font-bold mb-4 text-cyan-400">Hybrid Cryptosystem</h1>
        <p class="text-gray-300 mb-8 text-lg max-w-xl">Encrypt your data securely with AES and RSA combined.</p>
        <a href="{{ route('login') }}" class="bg-cyan-400 text-gray-900 font-semibold py-3 px-6 rounded-lg hover:bg-cyan-300 transition">Get Started</a>
    </section>

    <!-- Features Section -->
    <section class="py-16 px-4 bg-gray-800">
        <div class="max-w-5xl mx-auto grid md:grid-cols-3 gap-8 text-center">
            <div class="bg-gray-700 p-6 rounded-lg">
                <h3 class="text-xl font-bold text-cyan-400 mb-2">AES Encryption</h3>
                <p class="text-gray-300">Fast and efficient symmetric encryption for large files.</p>
            </div>
            <div class="bg-gray-700 p-6 rounded-lg">
                <h3 class="text-xl font-bold text-cyan-400 mb-2">RSA Encryption</h3>
                <p class="text-gray-300">Asymmetric encryption for secure key exchange and small files.</p>
            </div>
            <div class="bg-gray-700 p-6 rounded-lg">
                <h3 class="text-xl font-bold text-cyan-400 mb-2">Hybrid Mode</h3>
                <p class="text-gray-300">Combines AES & RSA to provide security and performance together.</p>
            </div>
        </div>
    </section>

    <!-- Footer -->
    <footer class="bg-gray-800 py-6 text-center text-gray-400">
        &copy; {{ date('Y') }} Hybrid Cryptosystem. All rights reserved.
    </footer>

</body>
</html>
