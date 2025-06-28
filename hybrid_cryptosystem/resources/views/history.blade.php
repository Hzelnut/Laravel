<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>History</title>
    @vite('resources/css/app.css')
</head>
<body class="bg-gray-900 text-white">    <div class="py-12">
        <div class="max-w-7xl mx-auto sm:px-6 lg:px-8 space-y-10">
<!-- Back to Dashboard Button -->
<div class="flex justify-start mb-4">
    <a href="{{ route('dashboard') }}" class="bg-gray-500 hover:bg-gray-600 text-white font-bold py-2 px-4 rounded">
        ← Back to Dashboard
    </a>
</div>

            <!-- Reset Button -->
            <div class="flex justify-end mb-4">
                <form method="POST" action="{{ route('history.reset') }}">
                    @csrf
                    <button class="bg-red-500 hover:bg-red-600 text-white font-bold py-2 px-4 rounded">
                        Reset History
                    </button>
                </form>
            </div>

            <!-- Chart Section -->
<div class="bg-white p-6 rounded shadow-sm">
                <h2 class="text-xl font-bold mb-4 text-cyan-400">Encryption vs Decryption Time (seconds)</h2>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
<div class="bg-white p-4 rounded shadow">
                        <h2 class="text-center font-semibold mb-2 text-cyan-300">Encryption Duration</h2>
                        <canvas id="encryptionChart" height="200"></canvas>
                    </div>
<div class="bg-white p-4 rounded shadow">
                        <h2 class="text-center font-semibold mb-2 text-cyan-300">Decryption Duration</h2>
                        <canvas id="decryptionChart" height="200"></canvas>
                    </div>
                </div>
            </div>

<!-- Encryption Table -->
<div class="bg-white p-6 rounded shadow-sm">
    <h2 class="text-xl font-bold mb-4 text-gray-800">Encryption Logs</h2>
    <table class="table-auto w-full mb-6">
        <thead>
            <tr class="bg-gray-200 text-gray-800 text-left">
                <th class="px-4 py-2">#</th>
                <th class="px-4 py-2">File</th>
                <th class="px-4 py-2">Algo</th>
                <th class="px-4 py-2">Size</th>
                <th class="px-4 py-2">Time</th>
                <th class="px-4 py-2">Date</th>
            </tr>
        </thead>
        <tbody>
            @forelse($encryptionLogs as $log)
            <tr class="border-t border-gray-300 text-gray-700 hover:bg-gray-100">
                <td class="px-4 py-2">{{ $loop->iteration }}</td>
                <td class="px-4 py-2">{{ $log->file_name }}</td>
                <td class="px-4 py-2">{{ $log->algorithm }}</td>
                <td class="px-4 py-2">{{ $log->file_size }}</td>
                <td class="px-4 py-2">{{ $log->duration }}</td>
                <td class="px-4 py-2">{{ $log->created_at->format('d M Y H:i') }}</td>
            </tr>
            @empty
            <tr>
                <td colspan="6" class="text-center text-gray-500 py-4">No encryption logs found.</td>
            </tr>
            @endforelse
        </tbody>
    </table>
</div>

<!-- Decryption Table -->
<div class="bg-white p-6 rounded shadow-sm">
    <h2 class="text-xl font-bold mb-4 text-gray-800">Decryption Logs</h2>
    <table class="table-auto w-full mb-6">
        <thead>
            <tr class="bg-gray-200 text-gray-800 text-left">
                <th class="px-4 py-2">#</th>
                <th class="px-4 py-2">File</th>
                <th class="px-4 py-2">Algo</th>
                <th class="px-4 py-2">Size</th>
                <th class="px-4 py-2">Time</th>
                <th class="px-4 py-2">Date</th>
            </tr>
        </thead>
        <tbody>
            @forelse($decryptionLogs as $log)
            <tr class="border-t border-gray-300 text-gray-700 hover:bg-gray-100">
                <td class="px-4 py-2">{{ $loop->iteration }}</td>
                <td class="px-4 py-2">{{ $log->file_name }}</td>
                <td class="px-4 py-2">{{ $log->algorithm }}</td>
                <td class="px-4 py-2">{{ $log->file_size }}</td>
                <td class="px-4 py-2">{{ $log->duration }}</td>
                <td class="px-4 py-2">{{ $log->created_at->format('d M Y H:i') }}</td>
            </tr>
            @empty
            <tr>
                <td colspan="6" class="text-center text-gray-500 py-4">No decryption logs found.</td>
            </tr>
            @endforelse
        </tbody>
    </table>
</div>



        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        const encryptionChartData = {
            labels: {!! json_encode($encryptionLogs->pluck('algorithm')) !!},
            datasets: [{
                label: 'Encryption Duration (s)',
                data: {!! json_encode($encryptionLogs->pluck('duration')) !!},
                backgroundColor: 'rgba(75, 192, 192, 0.7)'
            }]
        };

        const decryptionChartData = {
            labels: {!! json_encode($decryptionLogs->pluck('algorithm')) !!},
            datasets: [{
                label: 'Decryption Duration (s)',
                data: {!! json_encode($decryptionLogs->pluck('duration')) !!},
                backgroundColor: 'rgba(255, 99, 132, 0.7)'
            }]
        };

        new Chart(document.getElementById('encryptionChart'), { type: 'bar', data: encryptionChartData });
        new Chart(document.getElementById('decryptionChart'), { type: 'bar', data: decryptionChartData });
    </script>
</body>
</html>
