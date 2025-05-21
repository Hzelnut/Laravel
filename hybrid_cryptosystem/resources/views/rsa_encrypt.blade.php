<x-app-layout>
    <div class="py-12">
        <div class="max-w-4xl mx-auto sm:px-6 lg:px-8">
            <div class="bg-white overflow-hidden shadow-sm sm:rounded-lg p-6">
                <h2 class="text-xl font-bold mb-4">RSA File Encryption</h2>

                <form method="POST" action="{{ route('encrypt.rsa') }}" enctype="multipart/form-data">
                    @csrf
                    <div class="mb-4">
                        <label class="block">File to Encrypt (max ~190 bytes):</label>
                        <input type="file" name="file" class="border rounded p-2 w-full" required>
                    </div>
                    <div class="mb-4">
                        <label class="block">Password (for private key):</label>
                        <input type="password" name="password" class="border rounded p-2 w-full" required>
                    </div>
                    <button type="submit" class="bg-indigo-500 text-white px-4 py-2 rounded">Encrypt and Download</button>
                </form>
            </div>
        </div>
    </div>
</x-app-layout>
