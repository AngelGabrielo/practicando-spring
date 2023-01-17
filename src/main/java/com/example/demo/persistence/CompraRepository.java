package com.example.demo.persistence;

import com.example.demo.domain.Purchase;
import com.example.demo.domain.repository.PurchaseRepository;
import com.example.demo.persistence.crud.CompraCrudRepository;
import com.example.demo.persistence.entity.Compra;
import com.example.demo.persistence.mapper.PurchaseMapper;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public class CompraRepository implements PurchaseRepository {
    private CompraCrudRepository compraCrudRepository;
    private PurchaseMapper mapper;

    CompraRepository(CompraCrudRepository compraCrudRepository, PurchaseMapper mapper) {
        this.compraCrudRepository = compraCrudRepository;
        this.mapper= mapper;
    }

    @Override
    public List<Purchase> getAll(){
        return mapper.toPurchases((List<Compra>) compraCrudRepository.findAll());
    }

    @Override
    public Optional<List<Purchase>> getByClient(String clientId){
        return compraCrudRepository.findByIdCliente(clientId).
                map(compras -> mapper.toPurchases(compras));
    }

    @Override
     public Purchase save(Purchase purchase){
       Compra compra = mapper.toCompra(purchase);
       compra.getProductos().forEach(producto -> producto.setCompra(compra));

       return mapper.toPurchase(compraCrudRepository.save(compra));
    }
}
