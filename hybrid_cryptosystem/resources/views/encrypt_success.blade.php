@extends('layouts.app')

@section('content')
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>

<script>
document.addEventListener('DOMContentLoaded', function() {
    Swal.fire({
        icon: 'success',
        title: 'Encryption Successful!',
        text: 'Your file is now ready to download.',
        confirmButtonText: 'Download Now'
    }).then((result) => {
        if (result.isConfirmed) {
            window.location.href = "{{ route('download.encrypted', ['filename' => $filename]) }}";
        }
    });
});
</script>
@endsection
