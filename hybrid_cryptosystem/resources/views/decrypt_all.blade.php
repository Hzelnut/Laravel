<x-app-layout>
    <div class="py-12">
        <div class="max-w-4xl mx-auto sm:px-6 lg:px-8">
            <div class="bg-white overflow-hidden shadow-sm sm:rounded-lg p-6">
                <h2 class="text-xl font-bold mb-4 text-center">File Decryption</h2>

                <form method="POST" action="{{ route('decrypt.auto') }}" enctype="multipart/form-data">
                    @csrf

                    <!-- Mode Selection -->
                    <div class="mb-4">
                        <label class="block font-medium">Select Decryption Mode:</label>
                        <select name="mode" id="mode" class="border rounded p-2 w-full" required>
                            <option value="AES">AES</option>
                            <option value="RSA">RSA</option>
                            <option value="HYBRID">Hybrid</option>
                        </select>
                    </div>

                    <!-- Encrypted File Upload -->
                    <div class="mb-4">
                        <label class="block">Encrypted file (.enc):</label>
                        <input type="file" name="file" class="border rounded p-2 w-full" required>
                    </div>

                    <!-- Private Key for RSA/Hybrid -->
                    <div class="mb-4" id="private-key-group" style="display: none;">
                        <label class="block">Private Key (.pem):</label>
                        <input type="file" name="private_key" id="private_key" class="border rounded p-2 w-full">
                    </div>

                    <!-- Password Field -->
                    <div class="mb-4">
                        <label class="block">Password:</label>
                        <input type="password" name="password" class="border rounded p-2 w-full" required>
                    </div>

                    <button type="submit" class="bg-green-600 text-white px-4 py-2 rounded w-full">
                        Decrypt and Download
                    </button>
                </form>
            </div>
        </div>
    </div>

    {{-- Decryption Manual --}}
<<div class="max-w-4xl mx-auto sm:px-6 lg:px-8 mt-6">
  <div class="bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg p-6">
    <h3 class="text-xl font-semibold mb-4 text-gray-900 dark:text-gray-100">
    How to Use the Decryption Tool
  </h3>
  <ol class="list-decimal list-inside space-y-2 text-gray-800 dark:text-gray-200">
    <li>
      <strong>Select Decryption Mode:</strong>
      <ul class="list-disc list-inside ml-4 text-gray-700 dark:text-gray-300">
        <li><em>AES:</em> Only a password is required.</li>
        <li><em>RSA:</em> Requires your private key (.pem) and its password.</li>
        <li><em>Hybrid:</em> Requires both your private key and password.</li>
      </ul>
    </li>
    <li>
      <strong>Upload Encrypted File:</strong> Choose the <code>.enc</code> file you received.
    </li>
    <li>
      <strong>Provide Your Private Key:</strong> (RSA/Hybrid only)
      Upload your <code>.pem</code> file you downloaded earlier.
    </li>
    <li>
      <strong>Enter Password:</strong>
      - AES: your encryption password.
      - RSA/Hybrid: the password that protects your private key.
    </li>
    <li>
      <strong>Decrypt:</strong> Click <code>Decrypt and Download</code> to retrieve your original file.
    </li>
    <li>
      <strong>Verify Integrity:</strong>
      Make sure the downloaded file opens correctly—if not, recheck your mode, key, or password.
    </li>
  </ol>
</div>


    <!-- JS to toggle .pem field visibility -->
    <script>
        const modeSelect = document.getElementById('mode');
        const privateKeyGroup = document.getElementById('private-key-group');
        const privateKeyInput = document.getElementById('private_key');

        function toggleFields() {
            const selected = modeSelect.value;

            if (selected === 'RSA' || selected === 'HYBRID') {
                privateKeyGroup.style.display = 'block';
                privateKeyInput.setAttribute('required', 'required');
            } else {
                privateKeyGroup.style.display = 'none';
                privateKeyInput.removeAttribute('required');
                privateKeyInput.value = '';
            }
        }

        modeSelect.addEventListener('change', toggleFields);
        window.addEventListener('DOMContentLoaded', toggleFields);
    </script>

    <!-- SweetAlert2 confirmation and download trigger -->
    @if(session('success') && session('download_url') && session('download_name'))
        <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
        <script>
            document.addEventListener('DOMContentLoaded', function () {
                Swal.fire({
                    title: 'Decryption Successful!',
                    text: '{{ session('success') }}',
                    icon: 'success',
                    confirmButtonText: 'Download Now'
                }).then(() => {
                    const a = document.createElement('a');
                    a.href = "{{ session('download_url') }}";
                    a.setAttribute('download', '{{ session('download_name') }}');
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                });
            });
        </script>
    @endif
</x-app-layout>
