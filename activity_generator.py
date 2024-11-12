import random
import json
import re

def parse_basestats(file_path):
    """
    Parses the basestats file and returns a dictionary with event statistics.
    Handles multi-word event names by splitting columns with two or more spaces.
    
    Args:
        file_path (str): Path to the basestats.txt file.
    
    Returns:
        dict: Dictionary where each key is an event name, and the value is another
              dictionary with mean, std_dev, min, max, weight, and type details.
    """
    basestats = {}
    with open(file_path, 'r') as f:
        # Skip the header line
        next(f)
        for line in f:
            # Use regex to split by two or more spaces
            parts = re.split(r'\s{2,}', line.strip())
            
            # Only process lines with enough columns to be an event
            if len(parts) >= 7:
                event_name = parts[0]
                mean = float(parts[1])
                std_dev = float(parts[2])
                min_val = float(parts[3]) if parts[3] != "0" else None
                max_val = float(parts[4]) if parts[4] != "0" else None
                weight = int(parts[5])
                data_type = parts[6]

                basestats[event_name] = {
                    'mean': mean,
                    'std_dev': std_dev,
                    'min': min_val,
                    'max': max_val,
                    'weight': weight,
                    'type': data_type
                }
    return basestats

import random
import json
import statistics

def generate_daily_activity(basestats):
    """
    Generates daily activity for each event based on the stats provided in basestats.

    Args:
        basestats (dict): Dictionary of basestats with mean, std_dev, min, max, weight, and type.

    Returns:
        dict: Dictionary of generated activity values for each event.
    """
    daily_activity = {}
    for event_name, stats in basestats.items():
        mean = stats['mean']
        std_dev = stats['std_dev']
        min_val = stats['min'] if stats['min'] is not None else 1  # Default to 1 if min is None
        max_val = stats['max'] if stats['max'] is not None else 10000
        event_type = stats['type']

        if event_type == 'C':  # Continuous
            value = max(min(random.gauss(mean, std_dev), max_val), min_val)
            daily_activity[event_name] = round(value, 2)
        elif event_type == 'D':  # Discrete
            value = int(round(random.gauss(mean, std_dev)))
            daily_activity[event_name] = max(min(value, int(max_val)), int(min_val))
    return daily_activity

def generate_activities(basestats, days, output_file="all_activities.txt"):
    """
    Generates activities for a given number of days and logs them into a single text file.

    Args:
        basestats (dict): Base statistics for each event.
        days (int): Number of days to simulate.
        output_file (str): Name of the file to save all daily activities.

    Returns:
        list: A list of daily activity dictionaries.
    """
    all_activities = []
    print("Starting event generation...")
    with open(output_file, 'w') as f:
        for day in range(1, days + 1):
            daily_activity = generate_daily_activity(basestats)
            all_activities.append(daily_activity)

            # Write daily activity to file
            f.write(f"Day {day} Activity:\n")
            for event_name, value in daily_activity.items():
                f.write(f"{event_name}: {value}\n")
            f.write("\n")
    
    print("Event generation complete.")
    return all_activities

def analyze_activities(all_activities):
    """
    Analyzes the generated activity data to calculate mean and standard deviation for each event.

    Args:
        all_activities (list): A list of dictionaries with daily activity values for each event.

    Returns:
        dict: A dictionary containing the mean and standard deviation for each event across all days.
    """
    print("Starting analysis phase...")
    analysis_results = {}
    # Gather all values for each event across all days
    event_totals = {}
    for daily_activity in all_activities:
        for event_name, value in daily_activity.items():
            if event_name not in event_totals:
                event_totals[event_name] = []
            event_totals[event_name].append(value)
    
    # Calculate mean and std deviation for each event
    for event_name, values in event_totals.items():
        mean = round(statistics.mean(values), 2)
        std_dev = round(statistics.stdev(values), 2) if len(values) > 1 else 0.0  # Avoid stdev error with single value
        analysis_results[event_name] = {"mean": mean, "std_dev": std_dev}
        print(f"Analysis for {event_name}: Mean = {mean}, Std Dev = {std_dev}")
    
    # Save analysis results to a file
    with open("analysis_results.txt", 'w') as f:
        f.write("Event Analysis Results:\n")
        for event_name, stats in analysis_results.items():
            f.write(f"{event_name}: Mean = {stats['mean']}, Std Dev = {stats['std_dev']}\n")
    
    print("Analysis phase complete. Results saved to analysis_results.txt")
    return analysis_results

# Example usage
if __name__ == "__main__":
    basestats_file = "basestats.txt"  # path to basestats.txt file
    days = int(input("Enter the number of days to generate activity for: "))
    basestats = parse_basestats(basestats_file)

    # Generate activities and save to a file
    all_activities = generate_activities(basestats, days, output_file="all_activities.txt")

    # Analyze activities and save analysis results to a file
    analysis_results = analyze_activities(all_activities)

