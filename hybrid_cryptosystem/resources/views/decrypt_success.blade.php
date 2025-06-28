@extends('layouts.app')

@section('content')
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
<script>
    document.addEventListener('DOMContentLoaded', function() {
        Swal.fire({
            title: 'Decryption Successful!',
            text: 'Your file is ready to download.',
            icon: 'success',
            confirmButtonText: 'Download Now'
        }).then((result) => {
            if (result.isConfirmed) {
            window.location.href = "{{ session('download_url') }}";
            }
        });
    });
</script>
@endsection
