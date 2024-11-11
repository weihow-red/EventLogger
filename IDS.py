import sys
import os

# Basic command line parsing
if len(sys.argv) != 5:
    print("Usage: <function> <events_file> <stats_file> <days>")
    sys.exit(1)

function, events_file, stats_file, days = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
print(f"Running function: {function}, Events file: {events_file}, Stats file: {stats_file}, Days: {days}")


def parse_events(file_path):
    '''
    Parses an events configuration file and extracts information about each event.

    Args:
        file_path (str): The path to the events file. The file should contain the number of events on the 
                         first line, followed by lines for each event in the format:
                         Event name:[CD]:minimum:maximum:weight

    Returns:
        dict: A dictionary where each key is an event name, and each value is another dictionary with 
              details about the event, including:
              - 'type' (str): 'C' for continuous or 'D' for discrete.
              - 'min' (float or None): The minimum allowed value for the event (or None if unspecified).
              - 'max' (float or None): The maximum allowed value for the event (or None if unspecified).
              - 'weight' (int): A positive integer weight used in the alert engine.

    Notes:
        Continuous events ('C') allow decimal values, while discrete events ('D') only allow integer values.
    '''
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


def parse_stats(file_path):
    '''
    Parses a statistics configuration file and extracts statistical information for each event.

    Args:
        file_path (str): The path to the statistics file. The file should contain the number of events on the 
                         first line, followed by lines for each event in the format:
                         Event name:mean:standard deviation

    Returns:
        dict: A dictionary where each key is an event name, and each value is another dictionary with 
              details about the event's statistics, including:
              - 'mean' (float): The mean value for the event.
              - 'std_dev' (float): The standard deviation for the event.

    Notes:
        The statistics in this file will be used to compare against event data for intrusion detection.
    '''
    
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
    '''
    Combines event statistics from the stats and events dictionaries,
    adds weight information from events, and saves the result to a text file.
    Returns a dictionary with the combined base statistics.
    '''
    
    basestats = {}  # Dictionary to store combined statistics for each event
    
    # Combine stats and weights from events and stats dictionaries
    for event_name, stat_values in stats.items():
        if event_name in events:
            combined_entry = {
                'mean': stat_values['mean'],
                'std_dev': stat_values['std_dev'],
                'min': events[event_name].get('min', 0),  # Replace None with 0
                'max': events[event_name].get('max', 0),  # Replace None with 0
                'weight': events[event_name]['weight']
            }
            basestats[event_name] = combined_entry
            print(f"Base stats: {event_name} -> {combined_entry}")
        else:
            print(f"Warning: {event_name} found in stats but not in events.")
    
    # Save basestats to a text file in a tab-separated format
    with open("basestats.txt", 'w') as f:
        # Write header with alignment
        f.write(f"{'Event Name':<15}\t{'Mean':<8}\t{'Std Dev':<8}\t{'Min':<8}\t{'Max':<8}\t{'Weight':<8}\n")
        
        # Write each event's stats with better alignment, handling None values as 0
        for event_name, data in basestats.items():
            min_val = data['min'] if data['min'] is not None else 0
            max_val = data['max'] if data['max'] is not None else 0
            
            # Format the line with the data, replacing None with 0
            line = f"{event_name:<15}\t{data['mean']:<8}\t{data['std_dev']:<8}\t{min_val:<8}\t{max_val:<8}\t{data['weight']:<8}\n"
            f.write(line)
    
    print("Base stats saved to basestats.txt")
    return basestats


def get_threshold(basestats):
    '''
    Calculates a threshold value based on the weights of events in the basestats dictionary.

    Args:
        basestats (dict): A dictionary where each key is an event name, and each value is a dictionary 
                          containing event statistics, including a 'weight' field with a positive integer.

    Returns:
        int: The calculated threshold, which is twice the sum of all event weights in basestats.

    Notes:
        This threshold can be used to set an alert level for an intrusion detection system. 
        By doubling the sum of event weights, this threshold can help in identifying abnormal activity 
        based on the cumulative significance of event weights.
    '''

    threshold = 0 # thershold to be 2 * sum for weights
    
    # loop through basestats and sum the weights
    for event_name in basestats:
        threshold += basestats[event_name]['weight']

    threshold = threshold * 2 # sum * 2

    print(f"threshold: {threshold}")
    return threshold


def validate_consistency(events, stats):
    '''
    Validates the consistency between the events and stats data.

    Args:
        events (dict): A dictionary where each key is an event name and each value is a dictionary containing 
                       details about the event, including:
                       - 'type' (str): Event type ('C' for continuous, 'D' for discrete).
                       - 'min' (float or None): Minimum allowed value for continuous events (or None if unspecified).
                       - 'max' (float or None): Maximum allowed value for continuous events (or None if unspecified).
        stats (dict): A dictionary where each key is an event name and each value is a dictionary containing 
                      statistical data for the event, including:
                      - 'mean' (float): Mean value for the event.
                      - 'std_dev' (float): Standard deviation for the event.

    Returns:
        list: A list of inconsistency messages, where each message is a string describing a specific inconsistency 
              between the events and stats data. Returns an empty list if no inconsistencies are found.

    Notes:
        - The function checks that the events listed in both `events` and `stats` are identical.
        - For continuous events with specified minimum and maximum values, it verifies if the mean in `stats` 
          falls within this range. If any inconsistency is found, an appropriate message is added to the list.
        - Prints all found inconsistencies to the console.
    '''

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
    
    '''
    Calculates potential intrusions by monitoring event deviations over a specified number of days, 
    and triggers alerts when deviations exceed a defined threshold.

    Args:
        events (dict): A dictionary where each key is an event name and each value is a dictionary containing 
                       details about the event, including:
                       - 'min' (float): Minimum allowed value for continuous events.
                       - 'weight' (int): A positive integer representing the event's significance.
        stats (dict): A dictionary where each key is an event name and each value is a dictionary containing 
                      statistical data for the event, including:
                      - 'mean' (float): Mean value for the event.
                      - 'std_dev' (float): Standard deviation for the event.
        days (int): The number of days over which to monitor and calculate potential intrusions.
        threshold (float, optional): The threshold score that triggers an alert for an event. Default is 2.0.

    Returns:
        list: A list of tuples, where each tuple contains:
              - `day` (int): The day number (from 1 to `days`).
              - `day_alerts` (list): A list of alert messages for that day if any events exceed the threshold, 
                                     or an empty list if no alerts are triggered.

    Notes:
        - For each event, the function calculates a `score` based on the deviation of the event's mean 
          from its minimum allowed value, weighted by the event's significance (`weight`).
        - Alerts are triggered when the score exceeds the specified `threshold`.
        - All alerts are printed to the console as they are triggered, and a message is printed if no alerts 
          are triggered throughout the monitoring period.
    '''

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
