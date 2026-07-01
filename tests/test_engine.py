from intelligence.engine import ThreatEngine


engine = ThreatEngine()

url = input("URL: ")

result = engine.analyze(url)

print()

print(result)
