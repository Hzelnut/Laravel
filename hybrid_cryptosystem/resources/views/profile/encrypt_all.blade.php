<x-app-layout>
  <div class="py-12">
    <div class="max-w-4xl mx-auto sm:px-6 lg:px-8">

      {{-- Encryption Card --}}
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
            <input
              type="text"
              name="filename"
              placeholder="e.g. secret_file.txt"
              class="border rounded p-2 w-full"
            >
          </div>

          {{-- Password --}}
          <div class="mb-4">
            <label class="border rounded p-2 w-full">Password</label>
            <input
              type="password"
              name="password"
              class="border rounded p-2 w-full"
              required
            >
          </div>

          {{-- Encryption mode --}}
          <div class="mb-4">
            <label class="border rounded p-2 w-full">Encryption Mode</label>
            <select
              name="method"
              id="method"
              onchange="toggleRecipient()"
              class="border rounded p-2 w-full"
              required
            >
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

          <button
            type="submit"
            class="bg-green-600 hover:bg-green-700 text-white font-semibold px-4 py-2 rounded w-full"
          >
            Encrypt and Download
          </button>
        </form>
      </div>

      {{-- User Manual --}}
      <div class="bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg p-6 mt-6">
        <h3 class="text-xl font-semibold mb-4 text-gray-900 dark:text-gray-100">
          How to Use the Encryption Tool
        </h3>
        <ol class="list-decimal list-inside space-y-2 text-gray-800 dark:text-gray-200">
          <li>
            <strong>Select File:</strong> Click “Choose File” and pick the file you want to encrypt.
          </li>
          <li>
            <strong>Output Filename (optional):</strong> Give your encrypted file a custom name,
            or leave blank to append <code>.enc</code> to the original.
          </li>
          <li>
            <strong>Password:</strong> Type a strong password. You’ll need this (and your private key
            for RSA/Hybrid) to decrypt later.
          </li>
          <li>
            <strong>Encryption Mode:</strong> Pick one:
            <ul class="list-disc list-inside ml-4 text-gray-700 dark:text-gray-300">
              <li><em>AES:</em> Fast symmetric encryption using your password.</li>
              <li><em>RSA:</em> Public-key encryption; password protects your private key.</li>
              <li><em>Hybrid:</em> AES for the file + RSA to secure the AES key (best for large files).</li>
            </ul>
          </li>
          <li>
            <strong>Recipient (RSA/Hybrid only):</strong> Choose the user whose public key to use.
          </li>
          <li>
            <strong>Encrypt:</strong> Click <code>Encrypt and Download</code> to get your <code>.enc</code> file.
          </li>
        </ol>
      </div>

    </div>
  </div>

  <script>
    function toggleRecipient() {
      const method = document.getElementById('method').value;
      document.getElementById('recipient-section').style.display =
        (method === 'RSA' || method === 'HYBRID') ? 'block' : 'none';
    }
    document.addEventListener('DOMContentLoaded', toggleRecipient);
  </script>
</x-app-layout>
