import sys
import os

# Basic command line parsing
if len(sys.argv) != 5:
    print("Usage: <function> <events_file> <stats_file> <days>")
    sys.exit(1)

function, events_file, stats_file, days = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
print(f"Running function: {function}, Events file: {events_file}, Stats file: {stats_file}, Days: {days}")

# load event file and store as dictionary
def parse_events(file_path):
    events = {} # a dictionary of dictionary to store the event information

    # open n read file
    with open(file_path, 'r') as f:
        event_count = int(f.readline().strip())

        # for each row in file
        for _ in range(event_count):
            # delimiter by ':'
            line = f.readline().strip().split(':')

            # data format {Logins : {'type': 'D', 'min': 0.0, 'max': None, 'weight': 2}}
            event_name, event_type, min_val, max_val, weight = line[0], line[1], line[2], line[3], line[4]

            # store in event dictionary
            events[event_name] = {
                'type': event_type,
                'min': float(min_val) if min_val else None,
                'max': float(max_val) if max_val else None,
                'weight': int(weight)
            }
            print(f"File events: {event_name} -> {events[event_name]}")
    return events

# load stats file and store as dictionary
def parse_stats(file_path):
    stats = {}  # a dictionary of dictionary to store the event information

    # open n read file
    with open(file_path, 'r') as f:
        event_count = int(f.readline().strip())
        
        # for each row in file
        for _ in range(event_count):
            # delimiter by ':'
            line = f.readline().strip().split(':')

            # data format {Logins : {'mean': 4.0, 'std_dev': 1.5}}
            event_name, mean, std_dev = line[0], float(line[1]), float(line[2])
            stats[event_name] = {
                'mean': mean,
                'std_dev': std_dev
            }
            print(f"File stats: {event_name} -> {stats[event_name]}")
    return stats


def get_basestats(events, stats):
    basestats = {} # a dictionary of dictionary to store the event information
    
    for event_name, stat_values in stats.items():
        # Check if event exists in both stats and events dictionaries
        if event_name in events:
            combined_entry = {
                'mean': stat_values['mean'],
                'std_dev': stat_values['std_dev'],
                'weight': events[event_name]['weight']
            }
            basestats[event_name] = combined_entry
            print(f"Base stats: {event_name} -> {basestats[event_name]}")
        else:
            print(f"Warning: {event_name} found in stats but not in events.")
    
    # save as text file in the same format
    with open("basestats.txt", 'w') as f:
        for event_name, data in basestats.items():
            # Format the line as "Event:mean:std_dev:weight:"
            line = f"{event_name}:{data['mean']}:{data['std_dev']}:{data['weight']}:\n"
            f.write(line)

    return basestats

def get_threshold(basestats):
    threshold = 0 # thershold to be 2 * sum for weights
    
    # loop through basestats and sum the weights
    for event_name in basestats:
        threshold += basestats[event_name]['weight']

    threshold = threshold * 2 # sum * 2

    print(f"threshold: {threshold}")
    return threshold

def validate_consistency(events, stats):
    inconsistencies = []
    
    # Check if both files specify the same events
    event_names = set(events.keys())
    stat_names = set(stats.keys())
    if event_names != stat_names:
        inconsistencies.append("Mismatch in event names between Events and Stats files.")
    
    for event_name in events:
        event = events[event_name]
        if event_name in stats:
            stat = stats[event_name]
            if event['type'] == 'C' and (event['min'] is not None and event['max'] is not None):
                if stat['mean'] < event['min'] or stat['mean'] > event['max']:
                    inconsistencies.append(f"{event_name}: mean is outside of specified min/max range.")

    if inconsistencies:
        print("Inconsistencies found:")
        for inc in inconsistencies:
            print(f"- {inc}")
    else:
        print("No inconsistencies found.")
    
    return inconsistencies


def calculate_intrusion(events, stats, days, threshold=2.0):
    alerts = []
    for day in range(1, days + 1):
        day_alerts = []
        print(f"Day {day} alerts:")

        for event_name, event in events.items():
            stat = stats[event_name]
            deviation = abs(stat['mean'] - event['min']) / stat['std_dev'] if stat['std_dev'] else 0
            score = deviation * event['weight']

            if score > threshold:  # Define a threshold to trigger alerts
                alert_msg = f"Alert for {event_name}: Score {score} exceeds threshold"
                day_alerts.append(alert_msg)
                print(alert_msg)

        alerts.append((day, day_alerts))
    
    if not any(day_alerts for _, day_alerts in alerts):
        print("No alerts triggered across the monitoring period.")
        
    return alerts


if __name__ == "__main__":
    print(f"Starting Intrusion Detection System with {function} mode.")
    events = parse_events(events_file)
    stats = parse_stats(stats_file)
    basestats = get_basestats(events, stats)
    threshold = get_threshold(basestats)

    # Validate consistency
    inconsistencies = validate_consistency(events, stats)
    
    # If no inconsistencies, proceed with IDS
    if not inconsistencies:
        calculate_intrusion(events, stats, days)

#testing