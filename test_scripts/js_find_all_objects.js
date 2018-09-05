/*
  this scripts finds all objects/methods/propertes recursively from javascript engine. 
  tested on adobe reader js engine, (for fuzzing purpose).
*/
var visited = [] ;

visited.push(visited);

function already_visited(obj) {
  for(var i = 0; i < visited.length; i++) { 
    if (visited[i] == obj)
      return true;
  }
  return false;
} 

var what = function(obj) {
  var name = obj.toString(); try { obj.toString().match(/ (\w+)/)[1]; } catch(e) {}; return name;
};

function iterate_recursive(obj) {
    console.log("# [R] " + what(obj));
    visited.push(obj);
    var name_obj = what(obj);
    for (var property in obj) {
      try { 
        if (obj.hasOwnProperty(property)) {
            if (typeof obj[property] == "object")
                { 
                  console.log("<" + name_obj + "_object> = " + property + " " + obj[property]);  
                  if (!already_visited(obj[property]))
                  {
                    if (obj[property] != null && obj[property] != undefined)
                      iterate_recursive(obj[property]);
                  }
                }
            else if (typeof obj[property] == "function")
                { console.log("<" + name_obj + "_method> = " + property);  }
            else
            { console.log("<" + name_obj + "_property> = " +  property);  } 
        } else { 
          //console.log("[N] " + property);
          if (typeof obj[property] == "function")
                { console.log("<" + name_obj + "_method> = " + property);  }
            else
            { console.log("<" + name_obj + "_property> = " +  property);  }
        }  
      } catch (e) { console.log("# [E] " + property + " -> " + e); }
    }
}

function iterate(obj) {
    console.log("this is " + obj)
    for (var property in obj) {
      try { 
        if (obj.hasOwnProperty(property)) {
            if (typeof obj[property] == "object")
                { console.log("[O] " + property); }
            if (typeof obj[property] == "function")
                { console.log("[F] " + property);  }
            else
            { console.log("[P] " + property);  } 
        } else { 
          console.log("[N] " + property);
        } 
      } catch (e) { console.log("[E] " + property + " -> " + e); } 
    }
}

iterate(this);
