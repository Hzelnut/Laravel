<x-app-layout>
    <x-slot name="header">
        <h2 class="font-semibold text-xl text-gray-800 dark:text-gray-200 leading-tight">
            {{ __('Dashboard') }}
        </h2>
    </x-slot>

    <div class="py-12">
        <div class="max-w-7xl mx-auto sm:px-6 lg:px-8 space-y-4">

            <div class="bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg">
                <div class="p-6 text-gray-900 dark:text-gray-100">
                    {{ __("You're logged in!") }}
                </div>
            </div>

            {{-- 🔐 Private Key Download Section --}}
            <div class="bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg">
                <div class="p-6 text-gray-900 dark:text-gray-100">
                    <h3 class="text-lg font-bold mb-2">Your Private Key</h3>

                    @if(auth()->user()->private_key)
                        <button onclick="confirmDownload()" class="px-4 py-2 bg-yellow-500 hover:bg-yellow-600 text-white font-semibold rounded">
                            Download My Private Key
                        </button>
                    @else
                        <p class="text-red-400">No private key found. Please contact support.</p>
                    @endif
                </div>
            </div>

        </div>
    </div>

    {{-- ✅ SweetAlert2 CDN --}}
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script>
        function confirmDownload() {
            Swal.fire({
                title: 'Download Private Key?',
                text: "Make sure to store this file securely. You need it to decrypt files. If you lose it, recovery is not possible.",
                icon: 'warning',
                showCancelButton: true,
                confirmButtonText: 'Download',
                cancelButtonText: 'Cancel'
            }).then((result) => {
                if (result.isConfirmed) {
                    window.location.href = '{{ route('download.private.key') }}';
                }
            });
        }
    </script>
</x-app-layout>
