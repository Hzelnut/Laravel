@if (session('success') && session('download_url'))
<script>
Swal.fire({
  title: 'Success!',
  text: "{{ session('success') }}",
  icon: 'success',
  confirmButtonText: 'Download'
}).then((result) => {
  if (result.isConfirmed) {
    window.open("{{ session('download_url') }}", "_blank");
  }
});
</script>
@endif
