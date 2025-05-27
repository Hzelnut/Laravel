@extends('layouts.app')

@section('content')
<div class="container mt-4">
    <h3 class="mb-4">🔐 RSA File Encryption</h3>

    <form method="POST" action="{{ route('encrypt.rsa') }}" enctype="multipart/form-data">
        @csrf

        <div class="mb-3">
            <label for="file" class="form-label">Select File to Encrypt:</label>
            <input type="file" name="file" class="form-control" required>
            @error('file') <div class="text-danger">{{ $message }}</div> @enderror
        </div>

        <div class="mb-3">
            <label for="filename" class="form-label">Output Filename (without .enc):</label>
            <input type="text" name="filename" class="form-control">
            @error('filename') <div class="text-danger">{{ $message }}</div> @enderror
        </div>

        <div class="mb-3">
            <label for="password" class="form-label">Private Key Password (optional):</label>
            <input type="password" name="password" class="form-control">
            @error('password') <div class="text-danger">{{ $message }}</div> @enderror
        </div>

        <button type="submit" class="btn btn-primary">Encrypt with RSA</button>
    </form>
</div>
@endsection
