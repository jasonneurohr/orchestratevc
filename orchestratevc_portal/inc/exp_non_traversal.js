// Using projection to filter the result ?projection={"x":1, "y":1}'

// Get the data
$.getJSON('http://localhost:5000/api/v1/ciscoExpLicUtil', function (results) {
    console.log(results)

    // Split labels and non_traversal_in_use data into seperate arrays
    var labels = [], non_traversal_in_use = []
    $.each(results._items, function( key, val ) {
        labels.push(val.time_stamp)
        non_traversal_in_use.push(val.non_traversal_in_use)
    });
    //console.log(time_stamp)
    //console.log(non_traversal_in_use)

    // Create the chart.js data structure using the arrays
    var myChart = {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                data: non_traversal_in_use,
                fill: false,
            }]
        }
    };

    // Get the context of the canvas element we want to select
    var ctx = document.getElementById("ExpLicUtil-test").getContext("2d");
    // Instantiate a new chart
    window.myLine = new Chart(ctx, myChart);
});
