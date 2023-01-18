package com.example.demo.web.controller;

import com.example.demo.domain.Product;
import com.example.demo.domain.service.ProductService;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/products")
public class ProductController {
    private ProductService productService;

    ProductController(ProductService productService) {
        this.productService =productService;
    }

    @ApiOperation("Get all supermarket products")
    @ApiResponse(code = 200, message = "OK")
    @GetMapping("/all")
    public ResponseEntity<List<Product>> getAll() {
        return new ResponseEntity<>(productService.getAll(), HttpStatus.OK);
    }

    @ApiOperation("Search a product with an id")
    @ApiResponses({
            @ApiResponse(code = 200, message = "OK") ,
            @ApiResponse(code = 404, message = "Product not found")
    })
    @GetMapping("/{productId}")
    public ResponseEntity<Product> getProduct(@ApiParam(value = "The id of the product", required = true, example = "7")
                                                  @PathVariable("productId") int productId) {
        return productService.getProduct(productId)
                .map(product -> new ResponseEntity<>(product, HttpStatus.OK))
                .orElse(new ResponseEntity<>(HttpStatus.NOT_FOUND));
    }

    @ApiOperation("Search a product with a category")
    @ApiResponse(code = 200, message = "OK")
    @GetMapping("/category/{categoryId}")
    public ResponseEntity<List<Product>> getByCategory(@PathVariable("categoryId")int categoryId){
        return productService.getByCategory(categoryId).
                map(products -> new ResponseEntity<>(products, HttpStatus.OK))
                .orElse(new ResponseEntity<>(HttpStatus.NOT_FOUND));
    }

    @PostMapping("/save")
    public ResponseEntity<Product> save(@RequestBody Product product){
        return new ResponseEntity<>(productService.save(product), HttpStatus.CREATED);
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity delete(@PathVariable("id") int productId){
        if(productService.delete(productId))
            return new ResponseEntity<>(HttpStatus.OK);

        else
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

}
