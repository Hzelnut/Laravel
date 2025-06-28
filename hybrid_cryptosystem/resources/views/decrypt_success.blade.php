@extends('layouts.app')

@section('content')
<div class="container mx-auto px-4 py-8 text-center">
  <h2 class="text-2xl font-bold text-cyan-400 mb-4">Decryption Complete</h2>
  <p>Your file has been successfully decrypted.</p>
</div>

<script>
Swal.fire({
  title: 'Success!',
  text: "Your file has been decrypted successfully.",
  icon: 'success',
  confirmButtonText: 'Download'
}).then((result) => {
  if (result.isConfirmed) {
    window.open("{{ $download_url }}", "_blank");
  }
});
</script>
@endsection
