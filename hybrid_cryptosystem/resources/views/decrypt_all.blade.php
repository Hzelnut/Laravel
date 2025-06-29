@extends('layouts.app')

@section('content')
<div class="container mx-auto px-4 py-8">
  <h2 class="text-2xl font-bold text-center mb-6 text-cyan-400">Decrypt Your File</h2>

  <form action="{{ route('decrypt.auto') }}" method="POST" enctype="multipart/form-data" class="max-w-md mx-auto bg-gray-800 p-6 rounded-lg shadow-md">
    @csrf

    <!-- Algorithm selection -->
    <div class="mb-4">
      <label for="algorithm" class="block text-sm font-medium text-gray-300">Select Algorithm</label>
      <select name="algorithm" id="algorithm" required class="mt-2 w-full px-4 py-2 bg-white text-black rounded-lg focus:outline-none">
        <option value="">-- Select Algorithm --</option>
        <option value="AES">AES</option>
        <option value="RSA">RSA</option>
        <option value="HYBRID">Hybrid</option>
      </select>
    </div>

    <!-- File input -->
    <div class="mb-4" id="fileInput">
      <label for="file" class="block text-sm font-medium text-gray-300">Select Encrypted File</label>
      <input type="file" name="file" id="file" required class="mt-2 w-full px-4 py-2 bg-white text-black rounded-lg focus:outline-none">
    </div>

    <!-- Private key -->
    <div class="mb-4 hidden" id="privateKeyInput">
      <label for="private_key" class="block text-sm font-medium text-gray-300">Private Key (RSA / Hybrid only)</label>
      <input type="file" name="private_key" id="private_key" class="mt-2 w-full px-4 py-2 bg-white text-black rounded-lg focus:outline-none">
    </div>

    <!-- Password -->
    <div class="mb-6 hidden" id="passwordInput">
      <label for="password" class="block text-sm font-medium text-gray-300">Decryption Password</label>
      <input type="password" name="password" id="password" class="mt-2 w-full px-4 py-2 bg-white text-black rounded-lg focus:outline-none">
    </div>

    <button type="submit" class="w-full bg-cyan-400 hover:bg-cyan-500 text-black font-semibold py-2 px-4 rounded-lg">Decrypt File</button>
  </form>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
  const algorithm = document.getElementById('algorithm');
  const passwordInput = document.getElementById('passwordInput');
  const privateKeyInput = document.getElementById('privateKeyInput');

  algorithm.addEventListener('change', function() {
    const selected = this.value;

    // Reset visibility
    passwordInput.classList.add('hidden');
    privateKeyInput.classList.add('hidden');

    if (selected === 'AES') {
      passwordInput.classList.remove('hidden');
    } else if (selected === 'RSA') {
      privateKeyInput.classList.remove('hidden');
      passwordInput.classList.remove('hidden');
    } else if (selected === 'HYBRID') {
      privateKeyInput.classList.remove('hidden');
      passwordInput.classList.remove('hidden');
      // Move password after private key
      privateKeyInput.parentNode.insertBefore(passwordInput, privateKeyInput.nextSibling);
    }
  });
});
</script>

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


@endsection
