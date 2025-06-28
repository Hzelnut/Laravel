<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Profile</title>
    @vite('resources/css/app.css')
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
</head>
<body class="bg-gray-900 text-white p-8">

    <div class="max-w-xl mx-auto space-y-10">

        <h1 class="text-3xl font-bold mb-6">Profile Management</h1>

        <!-- Account Info -->
        <div class="bg-gray-800 p-6 rounded shadow">
            <h2 class="text-xl font-semibold mb-4">Account Info</h2>
            <p><strong>Name:</strong> {{ $user->name }}</p>
            <p><strong>Email:</strong> {{ $user->email }}</p>
        </div>

        <!-- Update name and email -->
        <div class="bg-gray-800 p-6 rounded shadow">
            <h2 class="text-xl font-semibold mb-4">Update Profile</h2>
            <form method="POST" action="{{ route('profile.update') }}" id="updateProfileForm">
                @csrf
                @method('PATCH')

                <div class="mb-4">
                    <label class="block text-sm font-medium">Name</label>
                    <input type="text" name="name" value="{{ old('name', $user->name) }}" class="mt-1 block w-full text-black rounded" required>
                </div>

                <div class="mb-4">
                    <label class="block text-sm font-medium">Email</label>
                    <input type="email" name="email" value="{{ old('email', $user->email) }}" class="mt-1 block w-full text-black rounded" required>
                </div>

                <button type="button" onclick="confirmUpdate()" class="bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded">Save Changes</button>
            </form>
        </div>

        <!-- Change password -->
        <div class="bg-gray-800 p-6 rounded shadow">
            <h2 class="text-xl font-semibold mb-4">Change Password</h2>
            <form method="POST" action="{{ route('password.update') }}" id="changePasswordForm">
                @csrf
                @method('PUT')

                <div class="mb-4">
                    <label class="block text-sm font-medium">New Password</label>
                    <input type="password" name="password" class="mt-1 block w-full text-black rounded" required>
                </div>

                <div class="mb-4">
                    <label class="block text-sm font-medium">Confirm New Password</label>
                    <input type="password" name="password_confirmation" class="mt-1 block w-full text-black rounded" required>
                </div>

                <button type="button" onclick="confirmPasswordChange()" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">Change Password</button>
            </form>
        </div>

        <!-- Delete account -->
        <div class="bg-gray-800 p-6 rounded shadow">
            <h2 class="text-xl font-semibold mb-4">Danger Zone</h2>
            <form method="POST" action="{{ route('profile.destroy') }}" id="deleteAccountForm">
                @csrf
                @method('DELETE')

                <button type="button" onclick="confirmDelete()" class="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded">Delete Account</button>
            </form>
        </div>

        <!-- Back button -->
        <div>
            <a href="{{ route('dashboard') }}" class="bg-gray-700 hover:bg-gray-800 text-white font-bold py-2 px-4 rounded">Back to Dashboard</a>
        </div>

    </div>

    <!-- SweetAlert Scripts -->
    <script>
        // Profile update confirmation
        function confirmUpdate() {
            Swal.fire({
                title: 'Save Changes?',
                icon: 'question',
                showCancelButton: true,
                confirmButtonColor: '#16a34a',
                cancelButtonColor: '#d33',
                confirmButtonText: 'Yes, save it!'
            }).then((result) => {
                if (result.isConfirmed) {
                    document.getElementById('updateProfileForm').submit();
                }
            });
        }

        // Change password confirmation
        function confirmPasswordChange() {
            Swal.fire({
                title: 'Change Password?',
                icon: 'question',
                showCancelButton: true,
                confirmButtonColor: '#2563eb',
                cancelButtonColor: '#d33',
                confirmButtonText: 'Yes, change it!'
            }).then((result) => {
                if (result.isConfirmed) {
                    document.getElementById('changePasswordForm').submit();
                }
            });
        }

        // Delete account confirmation
        function confirmDelete() {
            Swal.fire({
                title: 'Are you sure?',
                text: "Your account will be permanently deleted!",
                icon: 'warning',
                showCancelButton: true,
                confirmButtonColor: '#d33',
                cancelButtonColor: '#6b7280',
                confirmButtonText: 'Yes, delete it!'
            }).then((result) => {
                if (result.isConfirmed) {
                    document.getElementById('deleteAccountForm').submit();
                }
            });
        }
    </script>

    <!-- SweetAlert Success Messages -->
    @if(session('status'))
    <script>
        Swal.fire({
            icon: 'success',
            title: 'Success',
            text: '{{ session('status') }}',
            confirmButtonColor: '#3085d6'
        });
    </script>
    @endif

    @if ($errors->any())
    <script>
        Swal.fire({
            icon: 'error',
            title: 'Oops...',
            html: '{!! implode("<br>", $errors->all()) !!}',
            confirmButtonColor: '#d33'
        });
    </script>
    @endif

</body>
</html>
