import math
 
def calculate_area_of_circle(radius):
    """Calculate the area of a circle given its radius."""
    return math.pi * (radius ** 2)
 
def main():
    # Get user input
    radius = float(input("Enter the radius of the circle: "))
     
    # Calculate the area
    area = calculate_area_of_circle(radius)
     
    # Print the result
    print(f"The area of the circle with radius {radius} is {area:.2f}")
 
if __name__ == "__main__":
    main()
