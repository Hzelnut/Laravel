<x-app-layout>
    <div class="py-12">
        <div class="max-w-4xl mx-auto sm:px-6 lg:px-8">
            <div class="bg-white overflow-hidden shadow-sm sm:rounded-lg p-6">
                <h2 class="text-xl font-bold mb-4 text-center">Encrypt Your File</h2>

                <form method="POST" action="{{ route('encrypt.auto') }}" enctype="multipart/form-data">
                    @csrf

                    <!-- File upload -->
                    <div class="mb-4">
                        <label class="block font-medium">Select File</label>
                        <input type="file" name="file" class="border rounded p-2 w-full" required>
                    </div>

                    <!-- Output filename -->
                    <div class="mb-4">
                        <label class="block font-medium">Output Filename</label>
                        <input type="text" name="filename" class="border rounded p-2 w-full" placeholder="Optional">
                    </div>

                    <!-- Password (used for all modes) -->
                    <div class="mb-4">
                        <label class="block font-medium">Password (used for AES, RSA, and Hybrid)</label>
                        <input type="password" name="password" class="border rounded p-2 w-full" required>
                    </div>

                    <!-- Encryption Mode -->
                    <div class="mb-4">
                        <label class="block font-medium">Encryption Mode</label>
                        <select name="method" class="border rounded p-2 w-full" required>
                            <option value="AES">AES (Password-based)</option>
                            <option value="RSA">RSA (Public Key)</option>
                            <option value="HYBRID">Hybrid (AES + RSA)</option>
                        </select>
                    </div>

                    <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded w-full">
                        Encrypt and Download
                    </button>
                </form>
            </div>
        </div>
    </div>
</x-app-layout>
