<x-app-layout>

    <div class="py-12">
        <div class="max-w-4xl mx-auto sm:px-6 lg:px-8">
            <div class="bg-white overflow-hidden shadow-sm sm:rounded-lg p-6">
                <h2 class="text-xl font-bold mb-4 text-center">File Encryption</h2>
                <form method="POST" action="{{ route('encrypt.auto') }}" enctype="multipart/form-data">
                    @csrf

                    {{-- File input --}}
                    <div class="mb-4">
                        <label class="border rounded p-2 w-full">Select File</label>
                        <input type="file" name="file" class="border rounded p-2 w-full" required>
                    </div>

                    {{-- Output filename --}}
                    <div class="mb-4">
                        <label class="border rounded p-2 w-full">Output Filename (optional)</label>
                        <input type="text" name="filename" placeholder="e.g. secret_file.txt" class="border rounded p-2 w-full">
                    </div>

                    {{-- Password --}}
                    <div class="mb-4">
                        <label class="border rounded p-2 w-full">Password</label>
                        <input type="password" name="password" class="border rounded p-2 w-full" required>
                    </div>

                    {{-- Encryption mode --}}
                    <div class="mb-4">
                        <label class="border rounded p-2 w-full">Encryption Mode</label>
                        <select name="method" id="method" onchange="toggleRecipient()" class="border rounded p-2 w-full" required>
                            <option value="AES">AES (Password-based)</option>
                            <option value="RSA">RSA (Public Key)</option>
                            <option value="HYBRID">Hybrid (AES + RSA)</option>
                        </select>
                    </div>

                    {{-- Recipient selection (RSA / Hybrid only) --}}
                    <div class="mb-4" id="recipient-section" style="display: none;">
                        <label class="border rounded p-2 w-full">Select Recipient</label>
                        <select name="recipient_id" class="border rounded p-2 w-full">
                            @foreach(\App\Models\User::where('id', '!=', auth()->id())->get() as $user)
                                <option value="{{ $user->id }}">{{ $user->name }} ({{ $user->email }})</option>
                            @endforeach
                        </select>
                    </div>

                    <button type="submit" class="bg-green-600 text-white px-4 py-2 rounded w-full">
                        Encrypt and Download
                    </button>
                </form>
            </div>
        </div>
    </div>

    <script>
        function toggleRecipient() {
            const method = document.getElementById('method').value;
            const recipientSection = document.getElementById('recipient-section');
            recipientSection.style.display = (method === 'RSA' || method === 'HYBRID') ? 'block' : 'none';
        }
        document.addEventListener('DOMContentLoaded', toggleRecipient);
    </script>
</x-app-layout>
