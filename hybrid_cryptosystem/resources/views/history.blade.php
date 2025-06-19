<x-app-layout>
    <div class="py-12">
        <div class="max-w-6xl mx-auto sm:px-6 lg:px-8">
            <div class="bg-white p-6 rounded shadow-sm">
                <h2 class="text-xl font-bold mb-4">Encryption History</h2>

                <table class="table-auto w-full mb-6">
                    <thead>
                        <tr class="bg-gray-200 text-left">
                            <th class="px-4 py-2">#</th>
                            <th class="px-4 py-2">File</th>
                            <th class="px-4 py-2">Algo</th>
                            <th class="px-4 py-2">Size (bytes)</th>
                            <th class="px-4 py-2">Time (s)</th>
                            <th class="px-4 py-2">Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach($logs as $log)
                        <tr class="border-t">
                            <td class="px-4 py-2">{{ $loop->iteration }}</td>
                            <td class="px-4 py-2">{{ $log->file_name }}</td>
                            <td class="px-4 py-2">{{ $log->algorithm }}</td>
                            <td class="px-4 py-2">{{ $log->file_size }}</td>
                            <td class="px-4 py-2">{{ $log->duration }}</td>
                            <td class="px-4 py-2">{{ $log->created_at->format('d M Y H:i') }}</td>
                        </tr>
                        @endforeach
                    </tbody>
                </table>

                <canvas id="algoChart" height="100"></canvas>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        const ctx = document.getElementById('algoChart');
        const chart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: {!! json_encode($logs->pluck('algorithm')) !!},
                datasets: [{
                    label: 'Time (seconds)',
                    data: {!! json_encode($logs->pluck('duration')) !!},
                    backgroundColor: 'rgba(54, 162, 235, 0.6)'
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    </script>
</x-app-layout>
