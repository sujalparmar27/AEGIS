from core.csv_export import CSVExporter

exporter = CSVExporter()

file = exporter.export()

print(file)
