@extends('layouts.app')

@section('content')
<div class="container mx-auto px-4 py-8">
  <h2 class="text-2xl font-bold text-center mb-6 text-cyan-400">Encrypt Your File</h2>

  <form action="{{ route('encrypt.auto') }}" method="POST" enctype="multipart/form-data" class="max-w-md mx-auto bg-gray-800 p-6 rounded-lg shadow-md">
    @csrf

    <!-- File input -->
    <div class="mb-4">
      <label for="file" class="block text-sm font-medium text-gray-300">Select File</label>
      <input type="file" name="file" id="file" required class="mt-2 w-full px-4 py-2 bg-white text-black rounded-lg focus:outline-none">
    </div>

    <!-- Optional output filename -->
    <div class="mb-4">
      <label for="filename" class="block text-sm font-medium text-gray-300">Output Filename (Optional)</label>
      <input type="text" name="filename" id="filename" placeholder="Leave blank to keep original" class="mt-2 w-full px-4 py-2 bg-white text-black rounded-lg focus:outline-none">
    </div>

    <!-- Algorithm selector -->
    <div class="mb-4">
      <label for="algorithm" class="block text-sm font-medium text-gray-300">Select Encryption Algorithm</label>
      <select name="algorithm" id="algorithm" required class="mt-2 w-full px-4 py-2 bg-white text-black rounded-lg focus:outline-none">
        <option value="">-- Select Algorithm --</option>
        <option value="AES">AES (Symmetric)</option>
        <option value="RSA">RSA (Asymmetric)</option>
        <option value="HYBRID">Hybrid (AES + RSA)</option>
      </select>
    </div>

    <!-- Encryption password -->
    <div class="mb-6">
      <label for="password" class="block text-sm font-medium text-gray-300">Encryption Password</label>
      <input type="password" name="password" id="password" required placeholder="Encryption Password" class="mt-2 w-full px-4 py-2 bg-white text-black rounded-lg focus:outline-none">
    </div>


    <!-- Recipient selection -->
    <div class="mb-4" id="recipient_div">
      <label for="recipient_id" class="block text-sm font-medium text-gray-300">Select Recipient</label>
      <select name="recipient_id" id="recipient_id" class="mt-2 w-full px-4 py-2 bg-white text-black rounded-lg focus:outline-none">
        <option value="">-- Select Recipient --</option>
        @foreach($recipients as $recipient)
        <option value="{{ $recipient->id }}">{{ $recipient->name }} ({{ $recipient->email }})</option>
        @endforeach
      </select>
    </div>
    <button type="submit" class="w-full bg-cyan-400 hover:bg-cyan-500 text-black font-semibold py-2 px-4 rounded-lg">Encrypt File</button>


</form>
</div>



<!-- Script to hide recipient when AES is selected -->
<script>
document.addEventListener('DOMContentLoaded', function() {
  const algorithmSelect = document.getElementById('algorithm');
  const recipientDiv = document.getElementById('recipient_div');

  function toggleRecipient() {
    if (algorithmSelect.value === 'AES') {
      recipientDiv.style.display = 'none';
    } else {
      recipientDiv.style.display = 'block';
    }
  }

  algorithmSelect.addEventListener('change', toggleRecipient);
  toggleRecipient(); // initial call on page load
});
</script>
@endsection
